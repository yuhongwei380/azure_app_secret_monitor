import os
import msal
import requests
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv
import jwt
from flask import Flask, request, jsonify, Response

# 加载 .env
load_dotenv()

# 环境变量与默认值
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "your-client-id")
TENANT_ID = os.getenv("AZURE_TENANT_ID", "your-tenant-id")
CERT_PATH = os.getenv("CERT_FILE", "app_monitor_cert.pem")
KEY_PATH = os.getenv("KEY_FILE", "app_monitor_key.pem")

DEFAULT_EXPIRY_THRESHOLD_DAYS = int(os.getenv("EXPIRY_THRESHOLD_DAYS", "120"))
DEFAULT_SHOW_APPS_WITHOUT_PASSWORD = os.getenv("SHOW_APPS_WITHOUT_PASSWORD", "1") == "1"
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "300"))  # 结果缓存，默认 5 分钟
PORT = int(os.getenv("PORT", "8000"))
DEBUG_TOKEN = os.getenv("DEBUG_TOKEN", "0") == "1"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]
# 使用 applications，与 Azure 门户“应用注册 -> 证书和密码”一致
GRAPH_API_URL = "https://graph.microsoft.com/v1.0/applications"

app = Flask(__name__)

# 简单缓存
CACHE = {"data": None, "fetched_at": 0, "params": None}

# 从证书文件提取 thumbprint（用于 MSAL）
def get_cert_thumbprint(cert_path):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    if b"-----BEGIN CERTIFICATE-----" in cert_data:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    else:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
    return thumbprint

# 获取访问令牌（证书认证）
def get_access_token():
    thumbprint = get_cert_thumbprint(CERT_PATH)
    with open(KEY_PATH, "r") as f:
        private_key = f.read()

    app_msal = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential={
            "thumbprint": thumbprint,
            "private_key": private_key,
        }
    )

    result = app_msal.acquire_token_for_client(scopes=GRAPH_API_SCOPE)
    if "access_token" in result:
        if DEBUG_TOKEN:
            try:
                decoded = jwt.decode(result["access_token"], options={"verify_signature": False})
                print("DEBUG token:", {"roles": decoded.get("roles"), "appid": decoded.get("appid"), "iss": decoded.get("iss")})
            except Exception as e:
                print("DEBUG token decode error:", e)
        return result["access_token"]
    else:
        raise Exception(f"获取令牌失败: {result.get('error_description', result)}")

# 查询并整理即将过期的凭据
def fetch_expiring(threshold_days: int, show_without_password: bool):
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}

    cutoff = datetime.now(timezone.utc) + timedelta(days=threshold_days)

    params = {
        "$select": "id,displayName,appId,passwordCredentials,keyCredentials",
        "$top": "999",
    }
    url = GRAPH_API_URL

    expiring = []

    while url:
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()

        for app_obj in data.get("value", []):
            name = app_obj.get("displayName", "Unknown")
            app_id = app_obj.get("appId")

            password_creds = app_obj.get("passwordCredentials", []) or []
            key_creds = app_obj.get("keyCredentials", []) or []

            has_password = len(password_creds) > 0

            # 开关：隐藏“没有密码”的应用（即便它有证书）
            if not has_password and not show_without_password:
                continue

            # 密码到期
            for cred in password_creds:
                end_dt_str = cred.get("endDateTime")
                if not end_dt_str:
                    continue
                try:
                    end_dt = datetime.fromisoformat(end_dt_str.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if end_dt <= cutoff:
                    expiring.append({
                        "type": "Client Secret",
                        "app_name": name,
                        "app_id": app_id,
                        "cred_name": cred.get("displayName") or "Unnamed",
                        "expires_on": end_dt  # datetime 临时用于排序
                    })

            # 证书到期（常见为 usage='Verify' 的认证证书；若想统计全部证书，去掉 usage 判断）
            for cert in key_creds:
                if cert.get("usage") and cert.get("usage") != "Verify":
                    continue
                end_dt_str = cert.get("endDateTime")
                if not end_dt_str:
                    continue
                try:
                    end_dt = datetime.fromisoformat(end_dt_str.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if end_dt <= cutoff:
                    expiring.append({
                        "type": "Certificate",
                        "app_name": name,
                        "app_id": app_id,
                        "cred_name": cert.get("displayName") or "Unnamed",
                        "expires_on": end_dt
                    })

        next_link = data.get("@odata.nextLink")
        if next_link:
            url = next_link
            params = None
        else:
            url = None

    # 排序：Client Secret 优先；同类型按到期时间近的在前
    type_weight = {"Client Secret": 0, "Certificate": 1}
    expiring.sort(key=lambda x: (type_weight.get(x["type"], 99), x["expires_on"]))

    # 序列化时间
    for item in expiring:
        item["expires_on"] = item["expires_on"].isoformat()

    return expiring

# API：返回即将过期列表（支持 query 覆盖默认值）
@app.get("/api/expiring")
def api_expiring():
    try:
        days = request.args.get("days", type=int) or DEFAULT_EXPIRY_THRESHOLD_DAYS
        show_without_pwd_param = request.args.get("showWithoutPassword")
        if show_without_pwd_param is None:
            show_without_pwd = DEFAULT_SHOW_APPS_WITHOUT_PASSWORD
        else:
            show_without_pwd = show_without_pwd_param in ("1", "true", "True", "yes", "Y")

        # 简单缓存命中判断
        now = datetime.now().timestamp()
        params_key = (days, show_without_pwd)
        if (
            CACHE["data"] is not None
            and CACHE["params"] == params_key
            and (now - CACHE["fetched_at"] < CACHE_TTL_SECONDS)
        ):
            return jsonify({"params": {"days": days, "showWithoutPassword": show_without_pwd}, "cached": True, "items": CACHE["data"]})

        items = fetch_expiring(days, show_without_pwd)

        CACHE["data"] = items
        CACHE["fetched_at"] = now
        CACHE["params"] = params_key

        return jsonify({"params": {"days": days, "showWithoutPassword": show_without_pwd}, "cached": False, "items": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 网页：简单可视化（避免 f-string 与 JS 模板字面量冲突）
@app.get("/")
def index():
    default_days = str(DEFAULT_EXPIRY_THRESHOLD_DAYS)
    checked_attr = "checked" if DEFAULT_SHOW_APPS_WITHOUT_PASSWORD else ""

    html = """
<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>应用凭据到期监控</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, "Noto Sans", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif; margin: 20px; }
  .row { margin-bottom: 12px; }
  label { margin-right: 12px; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ddd; padding: 8px; }
  th { background: #f5f5f5; position: sticky; top: 0; }
  tr:nth-child(even) { background: #fafafa; }
  .tag { display:inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; color: #fff; }
  .secret { background:#0078d4; }
  .cert { background:#8c8c8c; }
  .warn { color:#b00020; font-weight: bold; }
  .muted { color:#666; }
</style>
</head>
<body>
  <h2>应用凭据到期监控</h2>
  <div class="row">
    <label>检查天数：
      <input type="number" id="days" min="1" value="__DAYS__" />
    </label>
    <label>
      <input type="checkbox" id="showWithoutPwd" __CHECKED__ />
      显示没有密码的应用
    </label>
    <button id="btnLoad">刷新</button>
    <span id="status" class="muted"></span>
  </div>

  <table id="tbl">
    <thead>
      <tr>
        <th>类型</th>
        <th>应用名称</th>
        <th>应用(客户端)ID</th>
        <th>凭据名称</th>
        <th>到期时间 (UTC)</th>
        <th>剩余天数</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>

<script>
function fmtDaysLeft(iso) {
  try {
    const d = new Date(iso);
    const now = new Date();
    const diffMs = d - now;
    const days = Math.floor(diffMs / 86400000); // 24*60*60*1000
    return days;
  } catch (e) {
    return "";
  }
}

async function loadData() {
  const days = document.getElementById("days").value || "__DAYS__";
  const show = document.getElementById("showWithoutPwd").checked ? 1 : 0;
  const url = `/api/expiring?days=${encodeURIComponent(days)}&showWithoutPassword=${show}`;
  const status = document.getElementById("status");
  status.textContent = "加载中...";
  try {
    const r = await fetch(url);
    const data = await r.json();
    const tbody = document.querySelector("#tbl tbody");
    tbody.innerHTML = "";
    if (data.error) {
      status.textContent = "错误：" + data.error;
      return;
    }
    const items = data.items || [];
    status.textContent = `共 ${items.length} 条${data.cached ? "（缓存）" : ""}`;
    for (const it of items) {
      const tr = document.createElement("tr");
      const typeTag = it.type === "Client Secret"
        ? '<span class="tag secret">Client Secret</span>'
        : '<span class="tag cert">Certificate</span>';
      const daysLeft = fmtDaysLeft(it.expires_on);
      tr.innerHTML = `
        <td>${typeTag}</td>
        <td>${it.app_name || ""}</td>
        <td>${it.app_id || ""}</td>
        <td>${it.cred_name || ""}</td>
        <td>${it.expires_on || ""}</td>
        <td class="${(typeof daysLeft === "number" && daysLeft <= 30) ? "warn" : ""}">${isNaN(daysLeft) ? "" : daysLeft}</td>
      `;
      tbody.appendChild(tr);
    }
  } catch (e) {
    status.textContent = "加载失败：" + e;
  }
}

document.getElementById("btnLoad").addEventListener("click", loadData);
window.addEventListener("load", loadData);
</script>
</body>
</html>
    """

    html = html.replace("__DAYS__", default_days).replace("__CHECKED__", checked_attr)
    return Response(html, mimetype="text/html")

if __name__ == "__main__":
    # 生产环境请使用 WSGI（gunicorn 等）；此处便于本地调试
    app.run(host="0.0.0.0", port=PORT, debug=False)

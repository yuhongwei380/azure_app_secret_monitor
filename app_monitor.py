import os
import msal
import requests
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv
import jwt
from flask import Flask, request, jsonify, render_template, Response
import time

# 加载 .env
load_dotenv()

# 环境变量与默认值
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "your-client-id")
TENANT_ID = os.getenv("AZURE_TENANT_ID", "your-tenant-id")
CERT_PATH = os.getenv("CERT_FILE", "app_monitor_cert.pem")
KEY_PATH = os.getenv("KEY_FILE", "app_monitor_key.pem")

DEFAULT_EXPIRY_THRESHOLD_DAYS = int(os.getenv("EXPIRY_THRESHOLD_DAYS", "120"))
DEFAULT_SHOW_APPS_WITHOUT_PASSWORD = os.getenv("SHOW_APPS_WITHOUT_PASSWORD", "1") == "1"
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "300"))
PORT = int(os.getenv("PORT", "8000"))
DEBUG_TOKEN = os.getenv("DEBUG_TOKEN", "0") == "1"
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_API_URL = "https://graph.microsoft.com/v1.0/applications"

app = Flask(__name__)
app.secret_key = SECRET_KEY

# 改进的缓存机制
class Cache:
    def __init__(self):
        self.data = None
        self.fetched_at = 0
        self.params = None
        self.ttl = CACHE_TTL_SECONDS
    
    def is_valid(self, params):
        current_time = time.time()
        return (
            self.data is not None
            and self.params == params
            and (current_time - self.fetched_at) < self.ttl
        )
    
    def update(self, data, params):
        self.data = data
        self.fetched_at = time.time()
        self.params = params

CACHE = Cache()

# 从证书文件提取 thumbprint
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

# 获取访问令牌
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
                        "expires_on": end_dt
                    })

            # 证书到期
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

    # 排序
    type_weight = {"Client Secret": 0, "Certificate": 1}
    expiring.sort(key=lambda x: (type_weight.get(x["type"], 99), x["expires_on"]))

    # 序列化时间
    for item in expiring:
        item["expires_on"] = item["expires_on"].isoformat()

    return expiring

# API 端点
@app.get("/api/expiring")
def api_expiring():
    try:
        days = request.args.get("days", type=int) or DEFAULT_EXPIRY_THRESHOLD_DAYS
        show_without_pwd_param = request.args.get("showWithoutPassword")
        if show_without_pwd_param is None:
            show_without_pwd = DEFAULT_SHOW_APPS_WITHOUT_PASSWORD
        else:
            show_without_pwd = show_without_pwd_param.lower() in ("1", "true", "yes", "y")

        params_key = (days, show_without_pwd)
        
        # 检查缓存
        if CACHE.is_valid(params_key):
            return jsonify({
                "params": {"days": days, "showWithoutPassword": show_without_pwd},
                "cached": True,
                "items": CACHE.data,
                "fetched_at": CACHE.fetched_at
            })

        # 获取新数据
        items = fetch_expiring(days, show_without_pwd)
        CACHE.update(items, params_key)

        return jsonify({
            "params": {"days": days, "showWithoutPassword": show_without_pwd},
            "cached": False,
            "items": items,
            "fetched_at": CACHE.fetched_at
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 健康检查端点
@app.get("/health")
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cache_age": time.time() - CACHE.fetched_at if CACHE.data else None
    })

# 主页面
@app.get("/")
def index():
    return render_template(
        "index.html",
        default_days=DEFAULT_EXPIRY_THRESHOLD_DAYS,
        show_without_password=DEFAULT_SHOW_APPS_WITHOUT_PASSWORD,
        cache_ttl=CACHE_TTL_SECONDS
    )

# 静态文件服务（如果需要）
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# 错误处理
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    # 创建必要的目录
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static", exist_ok=True)
    
    # 在开发模式下运行
    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=PORT,
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
        threaded=True
    )

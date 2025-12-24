import msal
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
import jwt  # 可选：解码 JWT token 用于调试
import os

# 加载 .env
load_dotenv()

# ================================
# 配置（建议从环境变量读取）
# ================================
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "your-client-id")
TENANT_ID = os.getenv("AZURE_TENANT_ID", "your-tenant-id")
CERT_PATH = os.getenv("CERT_FILE", "app_monitor_cert.pem")
KEY_PATH = os.getenv("KEY_FILE", "app_monitor_key.pem")

EXPIRY_THRESHOLD_DAYS = int(os.getenv("EXPIRY_THRESHOLD_DAYS", "120"))

# 新增：控制是否显示“没有密码（passwordCredentials 为空）的应用”的条目
# 0 表示隐藏，1 表示显示（默认显示）
SHOW_APPS_WITHOUT_PASSWORD = os.getenv("SHOW_APPS_WITHOUT_PASSWORD", "1") == "1"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]

# 注意：使用 applications，与 Azure 门户“应用注册 -> 证书和密码”一致
GRAPH_API_URL = "https://graph.microsoft.com/v1.0/applications"

# ================================
# 从证书文件提取 thumbprint（用于 MSAL）
# ================================
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

# ================================
# 获取访问令牌（证书认证）
# ================================
def get_access_token():
    thumbprint = get_cert_thumbprint(CERT_PATH)
    with open(KEY_PATH, "r") as f:
        private_key = f.read()

    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential={
            "thumbprint": thumbprint,
            "private_key": private_key,
        }
    )

    result = app.acquire_token_for_client(scopes=GRAPH_API_SCOPE)
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception(f"获取令牌失败: {result.get('error_description', result)}")

# ================================
# 获取并检查凭据（检验证书和密码的截止期限）
# ================================
def check_expiry():
    token = get_access_token()

    # 可选：调试 token 内容
    if os.getenv("DEBUG_TOKEN", "0") == "1":
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            print("✅ [DEBUG] Token 内容:")
            print(f"   Roles: {decoded.get('roles')}")
            print(f"   App ID: {decoded.get('appid')}")
            print(f"   Issuer: {decoded.get('iss')}")
            print()
        except Exception as e:
            print(f"⚠️ [DEBUG] 无法解码 token: {e}")

    headers = {"Authorization": f"Bearer {token}"}
    expiring = []

    cutoff = datetime.now(timezone.utc) + timedelta(days=EXPIRY_THRESHOLD_DAYS)

    # 仅选择需要的字段，减少负载
    params = {
        "$select": "id,displayName,appId,passwordCredentials,keyCredentials",
        "$top": "999",
    }
    url = GRAPH_API_URL

    while url:
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()

        for app in data.get("value", []):
            name = app.get("displayName", "Unknown")
            app_id = app.get("appId")

            password_creds = app.get("passwordCredentials", []) or []
            key_creds = app.get("keyCredentials", []) or []

            has_password = len(password_creds) > 0

            # 开关：隐藏“没有密码”的应用的条目（例如仅有证书的应用）
            if not has_password and not SHOW_APPS_WITHOUT_PASSWORD:
                continue

            # 检查“客户端密码”的到期时间
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
                        "expires_on": end_dt  # 暂存 datetime 便于排序
                    })

            # 检查“证书”的到期时间（认证用途通常为 usage='Verify'）
            for cert in key_creds:
                # 如需只统计认证证书，可保留下面这一行；若要统计全部证书，注释掉此行
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
                        "expires_on": end_dt  # 暂存 datetime 便于排序
                    })

        # 分页
        next_link = data.get("@odata.nextLink")
        if next_link:
            url = next_link
            params = None  # nextLink 已包含完整查询
        else:
            url = None

    # 优先展示：Client Secret > Certificate；同类型按到期时间升序
    type_weight = {"Client Secret": 0, "Certificate": 1}
    expiring.sort(key=lambda x: (type_weight.get(x["type"], 99), x["expires_on"]))

    # 格式化时间为字符串
    for item in expiring:
        item["expires_on"] = item["expires_on"].isoformat()

    return expiring

# ================================
# 主函数
# ================================
def main():
    print(f"🔍 检查未来 {EXPIRY_THRESHOLD_DAYS} 天内即将过期的应用凭据（应用注册的 证书 和 密码）...\n")
    try:
        expiring = check_expiry()
        if expiring:
            print(f"⚠️ 发现 {len(expiring)} 个即将过期的凭据：\n")
            for item in expiring:
                print(f"- [{item['type']}] {item['app_name']} ({item['app_id']})")
                print(f"  凭据名称: {item['cred_name']}")
                print(f"  到期时间: {item['expires_on']}")
                print()
        else:
            print("✅ 所有应用凭据均安全，无近期过期项。")
    except Exception as e:
        print(f"❌ 错误: {e}")

if __name__ == "__main__":
    main()

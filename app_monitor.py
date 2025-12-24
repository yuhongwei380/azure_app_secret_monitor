import msal
import requests
import json
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
import jwt  # 用于调试：解码 JWT token
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

EXPIRY_THRESHOLD_DAYS = 120

# ❗ 修复：移除 URL 和 scope 中的多余空格
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"  # ← 删除了空格
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]    # ← 删除了空格
GRAPH_API_URL = "https://graph.microsoft.com/v1.0/servicePrincipals"  # ← 删除了空格

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
# 获取并检查凭据
# ================================
def check_expiry():
    token = get_access_token()
    
    # ✅ 可选：调试 token 内容（按需取消注释）
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
    url = GRAPH_API_URL + "?$select=id,displayName,appId,passwordCredentials,keyCredentials"
    expiring = []
    cutoff = datetime.now(timezone.utc) + timedelta(days=EXPIRY_THRESHOLD_DAYS)

    while url:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        
        for sp in data.get("value", []):
            name = sp.get("displayName", "Unknown")
            app_id = sp.get("appId")
            
            # Check client secrets
            for cred in sp.get("passwordCredentials", []):
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
                        "expires_on": end_dt.isoformat()
                    })
            
            # Check certificates (only authentication certs)
            for cert in sp.get("keyCredentials", []):
                if cert.get("usage") != "Verify":
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
                        "expires_on": end_dt.isoformat()
                    })
        
        url = data.get("@odata.nextLink")
    
    return expiring

# ================================
# 主函数
# ================================
def main():
    print(f"🔍 检查未来 {EXPIRY_THRESHOLD_DAYS} 天内即将过期的应用凭据（使用证书认证）...\n")
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
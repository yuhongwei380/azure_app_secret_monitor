import os
import msal
import requests
import json
import threading
import time
import hmac
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv
import jwt
from flask import Flask, request, jsonify, render_template

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

# 告警相关配置文件
ALERT_CONFIG_FILE = Path("alert_config.json")
LAST_ALERTED_FILE = Path("last_alerted.json")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_API_URL = "https://graph.microsoft.com/v1.0/applications"

app = Flask(__name__)
app.secret_key = SECRET_KEY

# === 新增：日期格式化函数 ===
def format_expiry_date(date_value):
    """格式化日期为 YYYY-MM-DD 格式"""
    if not date_value:
        return None
    
    try:
        if isinstance(date_value, datetime):
            return date_value.strftime('%Y-%m-%d')
        elif isinstance(date_value, str):
            date_str = date_value.replace('Z', '+00:00')
            if '.' in date_str:
                date_str = date_str.split('.')[0] + '+00:00'
            try:
                dt = datetime.fromisoformat(date_str)
                return dt.strftime('%Y-%m-%d')
            except ValueError:
                for fmt in ['%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S%z']:
                    try:
                        dt = datetime.strptime(date_str, fmt)
                        return dt.strftime('%Y-%m-%d')
                    except ValueError:
                        continue
                return date_value
        return str(date_value)
    except Exception as e:
        print(f"⚠️ 日期格式化失败: {e}, 原始值: {date_value}")
        return str(date_value)

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

# === 告警配置工具函数 ===
def load_alert_config():
    if ALERT_CONFIG_FILE.exists():
        try:
            with open(ALERT_CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                config.setdefault("dingtalk_webhook", "")
                config.setdefault("dingtalk_secret", "")
                config.setdefault("alert_threshold_days", 30)
                config.setdefault("alert_check_interval_hours", 24)
                config.setdefault("min_alert_interval_hours", 24)
                config.setdefault("ignored_app_ids", [])
                return config
        except Exception as e:
            print(f"加载告警配置失败: {e}")
    return {
        "dingtalk_webhook": "",
        "dingtalk_secret": "",
        "alert_threshold_days": 30,
        "alert_check_interval_hours": 24,
        "min_alert_interval_hours": 24,
        "ignored_app_ids": []
    }

def save_alert_config(config):
    try:
        with open(ALERT_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"保存告警配置失败: {e}")

def load_last_alerted_times():
    if LAST_ALERTED_FILE.exists():
        try:
            with open(LAST_ALERTED_FILE, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                print("检测到旧版 last_alerted.json，正在迁移为新格式...")
                now = datetime.now(timezone.utc).isoformat()
                new_data = {f"{item[0]}|{item[1]}": now for item in data if isinstance(item, list) and len(item) == 2}
                save_last_alerted_times(new_data)
                return new_data
            elif isinstance(data, dict):
                return data
            else:
                print("last_alerted.json 格式异常，使用空配置")
                return {}
        except Exception as e:
            print(f"加载告警时间失败: {e}")
    return {}

def save_last_alerted_times(data):
    try:
        with open(LAST_ALERTED_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print(f"保存告警时间失败: {e}")

def sign_dingtalk(secret, timestamp):
    if not secret:
        return ""
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(
        secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256
    ).digest()
    sign = base64.b64encode(hmac_code).decode("utf-8")
    return sign

def send_dingtalk_message(webhook_url, message, secret=""):
    if not webhook_url or not message:
        return False
    try:
        timestamp = str(int(time.time() * 1000))
        headers = {"Content-Type": "application/json"}
        data = {"msgtype": "text", "text": {"content": message}}

        if secret:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(webhook_url)
            query = parse_qs(parsed.query)
            token = query.get("access_token", [None])[0]
            if not token:
                raise ValueError("Webhook URL 中缺少 access_token")
            url = f"https://oapi.dingtalk.com/robot/send?access_token={token}&timestamp={timestamp}&sign={sign_dingtalk(secret, timestamp)}"
        else:
            url = webhook_url

        resp = requests.post(url, json=data, headers=headers, timeout=10)
        success = resp.status_code == 200
        if not success:
            print(f"钉钉返回错误: {resp.text}")
        return success
    except Exception as e:
        print(f"钉钉消息发送失败: {e}")
        return False

# === Azure 相关函数 ===
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

# === 核心修改：新增 show_all 参数 ===
def fetch_expiring(threshold_days: int, show_without_password: bool, show_all: bool = False):
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}

    cutoff = None if show_all else datetime.now(timezone.utc) + timedelta(days=threshold_days)

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

            has_any_credential = len(password_creds) > 0 or len(key_creds) > 0

            if not has_any_credential and not show_without_password:
                continue
            
            for cred in password_creds:
                end_dt_str = cred.get("endDateTime")
                if not end_dt_str:
                    continue
                try:
                    end_dt = datetime.fromisoformat(end_dt_str.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if show_all or end_dt <= cutoff:
                    expiring.append({
                        "type": "Client Secret",
                        "app_name": name,
                        "app_id": app_id,
                        "cred_name": cred.get("displayName") or "Unnamed",
                        "expires_on": end_dt
                    })

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
                if show_all or end_dt <= cutoff:
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

    type_weight = {"Client Secret": 0, "Certificate": 1}
    expiring.sort(key=lambda x: (type_weight.get(x["type"], 99), x["expires_on"]))

    for item in expiring:
        item["expires_on"] = format_expiry_date(item["expires_on"])

    return expiring

# === 核心告警逻辑 ===
def perform_alert_check_and_send(force=False):
    config = load_alert_config()
    webhook = config.get("dingtalk_webhook", "").strip()
    secret = config.get("dingtalk_secret", "").strip()
    threshold = config.get("alert_threshold_days", 30)
    min_interval = config.get("min_alert_interval_hours", 24)

    if not webhook:
        return {"status": "skipped", "message": "未配置钉钉 Webhook"}

    try:
        items = fetch_expiring(threshold, show_without_password=True)
        ignored_app_ids = set(config.get("ignored_app_ids", []))
        last_alerted = load_last_alerted_times()
        now = datetime.now(timezone.utc)
        new_alerts = []

        for item in items:
            app_id = item["app_id"]
            cred_name = item["cred_name"]
            if not app_id or not cred_name:
                continue
            if app_id in ignored_app_ids:
                continue

            key = f"{app_id}|{cred_name}"
            last_time_str = last_alerted.get(key)

            can_alert = True
            if not force and last_time_str:
                try:
                    last_time = datetime.fromisoformat(last_time_str.replace("Z", "+00:00"))
                    if (now - last_time).total_seconds() < min_interval * 3600:
                        can_alert = False
                except:
                    pass

            if can_alert:
                new_alerts.append(item)

        if not new_alerts:
            msg = "无新告警（可能已在静默期）"
            if force:
                msg += "，但强制模式下仍无满足条件的凭据"
            return {"status": "no_alert", "message": msg}

        msg = f"[Azure 凭据到期告警]\n以下凭据将在 {threshold} 天内到期，请及时处理：\n\n"
        for item in new_alerts:
            expiry_date = item["expires_on"]
            try:
                expiry_dt = datetime.strptime(expiry_date, '%Y-%m-%d')
                days_left = (expiry_dt - now.replace(tzinfo=None)).days
                if days_left < 0:
                    days_left_text = f"已过期 {-days_left} 天"
                else:
                    days_left_text = f"剩余 {days_left} 天"
            except:
                days_left_text = "日期格式异常"
            
            msg += f"• {item['type']} | {item['app_name']} ({item['app_id']})\n"
            msg += f"  凭据: {item['cred_name']} | 到期: {expiry_date} | {days_left_text}\n\n"

        if send_dingtalk_message(webhook, msg, secret):
            for item in new_alerts:
                key = f"{item['app_id']}|{item['cred_name']}"
                last_alerted[key] = now.isoformat()
            save_last_alerted_times(last_alerted)
            return {
                "status": "success",
                "message": f"成功发送 {len(new_alerts)} 条告警",
                "count": len(new_alerts)
            }
        else:
            return {"status": "failed", "message": "钉钉消息发送失败"}

    except Exception as e:
        error_msg = f"告警检查异常: {str(e)}"
        print(error_msg)
        return {"status": "error", "message": error_msg}

# === Flask 路由 ===
@app.get("/api/expiring")
def api_expiring():
    try:
        days = request.args.get("days", type=int) or DEFAULT_EXPIRY_THRESHOLD_DAYS
        show_without_pwd_param = request.args.get("showWithoutPassword")
        show_all_param = request.args.get("showAll")

        if show_without_pwd_param is None:
            show_without_pwd = DEFAULT_SHOW_APPS_WITHOUT_PASSWORD
        else:
            show_without_pwd = show_without_pwd_param.lower() in ("1", "true", "yes", "y")

        show_all = show_all_param is not None and show_all_param.lower() in ("1", "true", "yes", "y")

        params_key = (days, show_without_pwd, show_all)

        if CACHE.is_valid(params_key):
            return jsonify({
                "params": {
                    "days": days,
                    "showWithoutPassword": show_without_pwd,
                    "showAll": show_all
                },
                "cached": True,
                "items": CACHE.data,
                "fetched_at": CACHE.fetched_at
            })

        items = fetch_expiring(days, show_without_pwd, show_all)
        CACHE.update(items, params_key)

        return jsonify({
            "params": {
                "days": days,
                "showWithoutPassword": show_without_pwd,
                "showAll": show_all
            },
            "cached": False,
            "items": items,
            "fetched_at": CACHE.fetched_at
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/health")
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cache_age": time.time() - CACHE.fetched_at if CACHE.data else None
    })

# === 告警配置 API ===
@app.get("/api/alert/config")
def get_alert_config():
    config = load_alert_config()
    return jsonify(config)

@app.post("/api/alert/config")
def update_alert_config():
    data = request.get_json()
    if not data:
        return jsonify({"error": "无效的 JSON 数据"}), 400

    webhook = (data.get("dingtalk_webhook") or "").strip()
    secret = (data.get("dingtalk_secret") or "").strip()
    threshold = data.get("alert_threshold_days", 30)
    check_interval = data.get("alert_check_interval_hours", 24)
    min_interval = data.get("min_alert_interval_hours", 24)

    try:
        threshold = int(threshold)
        check_interval = int(check_interval)
        min_interval = int(min_interval)
        if not (1 <= threshold <= 365):
            return jsonify({"error": "告警周期必须在 1-365 天之间"}), 400
        if not (1 <= check_interval <= 168):
            return jsonify({"error": "检查间隔必须在 1-168 小时之间（最多7天）"}), 400
        if not (1 <= min_interval <= 168):
            return jsonify({"error": "最小重发间隔必须在 1-168 小时之间（最多7天）"}), 400
        if min_interval > check_interval:
            return jsonify({"error": "最小重发间隔不能大于检查间隔"}), 400
    except (TypeError, ValueError):
        return jsonify({"error": "参数必须为整数"}), 400

    if webhook and not webhook.startswith("https://oapi.dingtalk.com/robot/send?"):
        return jsonify({"error": "钉钉 Webhook 地址格式不正确"}), 400

    config = load_alert_config()
    config["dingtalk_webhook"] = webhook
    config["dingtalk_secret"] = secret
    config["alert_threshold_days"] = threshold
    config["alert_check_interval_hours"] = check_interval
    config["min_alert_interval_hours"] = min_interval
    save_alert_config(config)

    return jsonify({"status": "success", "message": "告警配置已更新"})

@app.post("/api/alert/trigger")
def trigger_alert_now():
    result = perform_alert_check_and_send(force=True)
    if result["status"] in ("success", "no_alert", "skipped"):
        return jsonify(result)
    else:
        return jsonify(result), 500

@app.get("/api/alert/ignored")
def get_ignored_app_details():
    config = load_alert_config()
    ignored_app_ids = set(config.get("ignored_app_ids", []))
    if not ignored_app_ids:
        return jsonify([])

    try:
        threshold = config.get("alert_threshold_days", 30)
        all_items = fetch_expiring(threshold, show_without_password=True)
        ignored_items = [item for item in all_items if item["app_id"] in ignored_app_ids]
        return jsonify(ignored_items)
    except Exception as e:
        print(f"获取忽略应用详情失败: {e}")
        return jsonify([{"app_id": app_id} for app_id in ignored_app_ids])

@app.post("/api/alert/ignored")
def add_ignored_app_id():
    data = request.get_json()
    app_id = (data.get("app_id") or "").strip()
    if not app_id:
        return jsonify({"error": "app_id 不能为空"}), 400

    config = load_alert_config()
    ignored = config.setdefault("ignored_app_ids", [])
    if app_id not in ignored:
        ignored.append(app_id)
        save_alert_config(config)
    return jsonify({"status": "ignored", "app_id": app_id})

@app.delete("/api/alert/ignored")
def remove_ignored_app_id():
    data = request.get_json()
    app_id = (data.get("app_id") or "").strip()
    if not app_id:
        return jsonify({"error": "app_id 不能为空"}), 400

    config = load_alert_config()
    ignored = config.get("ignored_app_ids", [])
    config["ignored_app_ids"] = [aid for aid in ignored if aid != app_id]
    save_alert_config(config)
    return jsonify({"status": "removed", "app_id": app_id})

@app.get("/")
def index():
    return render_template(
        "index.html",
        default_days=DEFAULT_EXPIRY_THRESHOLD_DAYS,
        show_without_password=DEFAULT_SHOW_APPS_WITHOUT_PASSWORD,
        cache_ttl=CACHE_TTL_SECONDS
    )

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# === 后台线程 ===
def alert_check_worker():
    print("✅ 告警检查线程已启动")
    while True:
        try:
            config = load_alert_config()
            interval_hours = config.get("alert_check_interval_hours", 24)
            sleep_seconds = interval_hours * 3600

            result = perform_alert_check_and_send(force=False)
            status = result["status"]
            message = result["message"]
            if status == "success":
                print(f"✅ {message}")
            elif status == "no_alert":
                print("ℹ️ " + message)
            elif status == "skipped":
                print("⏭️ " + message)
            else:
                print(f"❌ {message}")

            time.sleep(sleep_seconds)

        except Exception as e:
            print(f"⚠️ 告警线程异常: {e}")
            time.sleep(300)

if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static", exist_ok=True)

    alert_thread = threading.Thread(target=alert_check_worker, daemon=True)
    alert_thread.start()

    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=PORT,
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
        threaded=True
    )

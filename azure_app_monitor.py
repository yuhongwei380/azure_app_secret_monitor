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
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import jwt
from flask import Flask, request, jsonify, render_template

# 加载 .env
load_dotenv()

# === 基础路径配置 (解决路径依赖问题) ===
BASE_DIR = Path(__file__).resolve().parent

# === 线程锁 (保证文件读写安全) ===
CONFIG_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()

# === 环境变量与默认值 ===
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "your-client-id")
TENANT_ID = os.getenv("AZURE_TENANT_ID", "your-tenant-id")

# 证书路径优先使用绝对路径，如果环境变量是相对路径，则基于 BASE_DIR
_cert_env = os.getenv("CERT_FILE", "app_monitor_cert.pem")
_key_env = os.getenv("KEY_FILE", "app_monitor_key.pem")
CERT_PATH = Path(_cert_env) if Path(_cert_env).is_absolute() else BASE_DIR / _cert_env
KEY_PATH = Path(_key_env) if Path(_key_env).is_absolute() else BASE_DIR / _key_env

DEFAULT_EXPIRY_THRESHOLD_DAYS = int(os.getenv("EXPIRY_THRESHOLD_DAYS", "120"))
DEFAULT_SHOW_APPS_WITHOUT_PASSWORD = os.getenv("SHOW_APPS_WITHOUT_PASSWORD", "1") == "1"
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "300"))
PORT = int(os.getenv("PORT", "8000"))
DEBUG_TOKEN = os.getenv("DEBUG_TOKEN", "0") == "1"
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")

# 配置文件路径
ALERT_CONFIG_FILE = BASE_DIR / "alert_config.json"
LAST_ALERTED_FILE = BASE_DIR / "last_alerted.json"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_API_URL = "https://graph.microsoft.com/v1.0/applications"

app = Flask(__name__)
app.secret_key = SECRET_KEY

# === MSAL 全局单例 ===
_MSAL_APP = None

# === 辅助函数 ===
def format_expiry_date(date_value):
    """格式化日期为 YYYY-MM-DD 格式，增强容错性"""
    if not date_value:
        return None
    
    try:
        if isinstance(date_value, datetime):
            return date_value.strftime('%Y-%m-%d')
        elif isinstance(date_value, str):
            # 统一处理时区标识
            date_str = date_value.replace('Z', '+00:00')
            # 去除毫秒
            if '.' in date_str and '+' in date_str:
                parts = date_str.split('.')
                timezone_part = parts[1][parts[1].find('+'):]
                date_str = parts[0] + timezone_part
            
            try:
                dt = datetime.fromisoformat(date_str)
                return dt.strftime('%Y-%m-%d')
            except ValueError:
                # 尝试其他常见格式
                for fmt in ['%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S%z', '%Y-%m-%d']:
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

# === 优化后的缓存类 ===
class Cache:
    def __init__(self):
        self._store = {}  # Key: params_tuple, Value: (timestamp, data)
        self.ttl = CACHE_TTL_SECONDS
        self.lock = threading.Lock()

    def get(self, params):
        with self.lock:
            if params in self._store:
                timestamp, data = self._store[params]
                if time.time() - timestamp < self.ttl:
                    return data, timestamp
                else:
                    del self._store[params] # 删除过期缓存
        return None, None

    def set(self, params, data):
        with self.lock:
            self._store[params] = (time.time(), data)

CACHE = Cache()

# === 配置管理 (带线程锁) ===
def load_alert_config():
    if ALERT_CONFIG_FILE.exists():
        try:
            with open(ALERT_CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            print(f"加载告警配置失败: {e}")
            config = {}
    else:
        config = {}
    
    # 设置默认值
    config.setdefault("dingtalk_webhook", "")
    config.setdefault("dingtalk_secret", "")
    config.setdefault("feishu_webhook", "")    # 新增：飞书
    config.setdefault("feishu_secret", "")     # 新增：飞书
    config.setdefault("alert_threshold_days", 30)
    config.setdefault("alert_check_interval_hours", 24)
    config.setdefault("min_alert_interval_hours", 24)
    config.setdefault("ignored_app_ids", [])
    return config

def save_alert_config(config):
    with CONFIG_LOCK:
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
            # 兼容旧版本列表格式
            if isinstance(data, list):
                print("检测到旧版 last_alerted.json，正在迁移...")
                now = datetime.now(timezone.utc).isoformat()
                new_data = {f"{item[0]}|{item[1]}": now for item in data if len(item) == 2}
                save_last_alerted_times(new_data)
                return new_data
            elif isinstance(data, dict):
                return data
            return {}
        except Exception as e:
            print(f"加载告警时间失败: {e}")
    return {}

def save_last_alerted_times(data):
    with STATE_LOCK:
        try:
            with open(LAST_ALERTED_FILE, "w") as f:
                json.dump(data, f)
        except Exception as e:
            print(f"保存告警时间失败: {e}")

# === 消息通知相关 ===
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

        url = webhook_url
        if secret:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(webhook_url)
            query = parse_qs(parsed.query)
            token_list = query.get("access_token")
            if token_list:
                token = token_list[0]
                sign = sign_dingtalk(secret, timestamp)
                url = f"https://oapi.dingtalk.com/robot/send?access_token={token}&timestamp={timestamp}&sign={sign}"
            
        resp = requests.post(url, json=data, headers=headers, timeout=10)
        success = resp.status_code == 200
        if not success:
            print(f"钉钉返回错误: {resp.text}")
        return success
    except Exception as e:
        print(f"钉钉消息发送失败: {e}")
        return False

def sign_feishu(secret, timestamp):
    """计算飞书签名"""
    if not secret:
        return ""
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(
        string_to_sign.encode("utf-8"),
        digestmod=hashlib.sha256
    ).digest()
    sign = base64.b64encode(hmac_code).decode("utf-8")
    return sign

def send_feishu_message(webhook_url, message, secret=""):
    """发送飞书消息"""
    if not webhook_url or not message:
        return False
    try:
        # 飞书要求 timestamp 为秒级整数
        timestamp = str(int(time.time()))
        headers = {"Content-Type": "application/json"}
        data = {
            "msg_type": "text",
            "content": {"text": message}
        }

        if secret:
            sign = sign_feishu(secret, timestamp)
            data["timestamp"] = timestamp
            data["sign"] = sign

        resp = requests.post(webhook_url, json=data, headers=headers, timeout=10)
        resp_json = resp.json()
        
        # 飞书成功返回 code: 0
        success = resp.status_code == 200 and resp_json.get("code") == 0
        if not success:
            print(f"飞书返回错误: {resp.text}")
        return success
    except Exception as e:
        print(f"飞书消息发送失败: {e}")
        return False

# === Azure 认证 (单例优化) ===
def get_cert_thumbprint(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    if b"-----BEGIN CERTIFICATE-----" in cert_data:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    else:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
    return thumbprint

def get_msal_app():
    """获取 MSAL 客户端单例，避免重复 IO"""
    global _MSAL_APP
    if _MSAL_APP is None:
        try:
            thumbprint = get_cert_thumbprint(CERT_PATH)
            with open(KEY_PATH, "r") as f:
                private_key = f.read()
            
            _MSAL_APP = msal.ConfidentialClientApplication(
                CLIENT_ID,
                authority=AUTHORITY,
                client_credential={
                    "thumbprint": thumbprint,
                    "private_key": private_key,
                }
            )
        except Exception as e:
            print(f"❌ 初始化 MSAL 客户端失败 (请检查证书路径): {e}")
            raise
    return _MSAL_APP

def get_access_token():
    app_msal = get_msal_app()
    # MSAL 库会自动处理 Token 缓存和刷新
    result = app_msal.acquire_token_for_client(scopes=GRAPH_API_SCOPE)
    
    if "access_token" in result:
        return result["access_token"]
    else:
        # 如果获取失败（如证书过期），重置 app 实例以便下次重试
        global _MSAL_APP
        _MSAL_APP = None
        raise Exception(f"获取令牌失败: {result.get('error_description', result)}")

# === 核心逻辑 ===
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
            
            # 检查 Secret
            for cred in password_creds:
                end_dt_str = cred.get("endDateTime")
                if not end_dt_str: continue
                try:
                    end_dt = datetime.fromisoformat(end_dt_str.replace("Z", "+00:00"))
                except ValueError: continue
                
                if show_all or (cutoff and end_dt <= cutoff):
                    expiring.append({
                        "type": "Client Secret",
                        "app_name": name,
                        "app_id": app_id,
                        "cred_name": cred.get("displayName") or "Unnamed",
                        "expires_on": end_dt
                    })

            # 检查证书
            for cert in key_creds:
                if cert.get("usage") and cert.get("usage") != "Verify":
                    continue
                end_dt_str = cert.get("endDateTime")
                if not end_dt_str: continue
                try:
                    end_dt = datetime.fromisoformat(end_dt_str.replace("Z", "+00:00"))
                except ValueError: continue
                
                if show_all or (cutoff and end_dt <= cutoff):
                    expiring.append({
                        "type": "Certificate",
                        "app_name": name,
                        "app_id": app_id,
                        "cred_name": cert.get("displayName") or "Unnamed",
                        "expires_on": end_dt
                    })

        # 分页处理
        next_link = data.get("@odata.nextLink")
        if next_link:
            url = next_link
            params = None
        else:
            url = None

    # 排序
    type_weight = {"Client Secret": 0, "Certificate": 1}
    expiring.sort(key=lambda x: (type_weight.get(x["type"], 99), x["expires_on"]))

    # 格式化日期
    for item in expiring:
        item["expires_on"] = format_expiry_date(item["expires_on"])

    return expiring

def perform_alert_check_and_send(force=False):
    config = load_alert_config()
    ding_webhook = config.get("dingtalk_webhook", "").strip()
    ding_secret = config.get("dingtalk_secret", "").strip()
    feishu_webhook = config.get("feishu_webhook", "").strip()
    feishu_secret = config.get("feishu_secret", "").strip()

    threshold = config.get("alert_threshold_days", 30)
    min_interval = config.get("min_alert_interval_hours", 24)

    if not ding_webhook and not feishu_webhook:
        return {"status": "skipped", "message": "未配置任何告警 Webhook"}

    try:
        items = fetch_expiring(threshold, show_without_password=True, show_all=False)
        ignored_app_ids = set(config.get("ignored_app_ids", []))
        last_alerted = load_last_alerted_times()
        now = datetime.now(timezone.utc)
        new_alerts = []

        for item in items:
            app_id = item["app_id"]
            cred_name = item["cred_name"]
            
            if not app_id or not cred_name: continue
            if app_id in ignored_app_ids: continue

            key = f"{app_id}|{cred_name}"
            last_time_str = last_alerted.get(key)
            
            can_alert = True
            if not force and last_time_str:
                try:
                    last_time = datetime.fromisoformat(last_time_str.replace("Z", "+00:00"))
                    # 检查是否在静默期内
                    if (now - last_time).total_seconds() < min_interval * 3600:
                        can_alert = False
                except:
                    pass

            if can_alert:
                new_alerts.append(item)

        if not new_alerts:
            msg = "无新告警（可能已在静默期）"
            return {"status": "no_alert", "message": msg}

        # 构建消息
        msg = f"[Azure 凭据到期告警]\n以下凭据将在 {threshold} 天内到期，请及时处理：\n\n"
        for item in new_alerts:
            expiry_date = item["expires_on"]
            try:
                expiry_dt = datetime.strptime(expiry_date, '%Y-%m-%d')
                days_left = (expiry_dt - now.replace(tzinfo=None)).days
                days_txt = f"剩余 {days_left} 天" if days_left >= 0 else f"已过期 {-days_left} 天"
            except:
                days_txt = ""
            
            msg += f"• {item['type']} | {item['app_name']}\n"
            msg += f"  AppID: {item['app_id']}\n"
            msg += f"  凭据: {item['cred_name']} | 到期: {expiry_date} ({days_txt})\n\n"

        # 发送逻辑
        send_results = []
        if ding_webhook:
            if send_dingtalk_message(ding_webhook, msg, ding_secret):
                send_results.append("钉钉成功")
            else:
                send_results.append("钉钉失败")
        
        if feishu_webhook:
            if send_feishu_message(feishu_webhook, msg, feishu_secret):
                send_results.append("飞书成功")
            else:
                send_results.append("飞书失败")

        if any("成功" in r for r in send_results):
            # 更新告警时间
            for item in new_alerts:
                key = f"{item['app_id']}|{item['cred_name']}"
                last_alerted[key] = now.isoformat()
            save_last_alerted_times(last_alerted)
            
            return {
                "status": "success", 
                "message": f"发送结果: {', '.join(send_results)}",
                "count": len(new_alerts)
            }
        else:
            return {"status": "failed", "message": f"所有发送失败: {', '.join(send_results)}"}

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

        show_without_pwd = DEFAULT_SHOW_APPS_WITHOUT_PASSWORD
        if show_without_pwd_param is not None:
            show_without_pwd = show_without_pwd_param.lower() in ("1", "true", "yes", "y")

        show_all = show_all_param is not None and show_all_param.lower() in ("1", "true", "yes", "y")

        params_key = (days, show_without_pwd, show_all)

        cached_items, fetched_at = CACHE.get(params_key)
        if cached_items is not None:
            return jsonify({
                "params": {"days": days, "showWithoutPassword": show_without_pwd, "showAll": show_all},
                "cached": True,
                "items": cached_items,
                "fetched_at": fetched_at
            })

        items = fetch_expiring(days, show_without_pwd, show_all)
        CACHE.set(params_key, items)
        
        _, new_fetched_at = CACHE.get(params_key)

        return jsonify({
            "params": {"days": days, "showWithoutPassword": show_without_pwd, "showAll": show_all},
            "cached": False,
            "items": items,
            "fetched_at": new_fetched_at or time.time()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/health")
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.get("/api/alert/config")
def get_alert_config_api():
    return jsonify(load_alert_config())

@app.post("/api/alert/config")
def update_alert_config():
    data = request.get_json()
    if not data:
        return jsonify({"error": "无效的 JSON 数据"}), 400

    try:
        threshold = int(data.get("alert_threshold_days", 30))
        check_interval = int(data.get("alert_check_interval_hours", 24))
        min_interval = int(data.get("min_alert_interval_hours", 24))
    except ValueError:
        return jsonify({"error": "数值参数必须为整数"}), 400

    config = load_alert_config()
    config["dingtalk_webhook"] = (data.get("dingtalk_webhook") or "").strip()
    config["dingtalk_secret"] = (data.get("dingtalk_secret") or "").strip()
    config["feishu_webhook"] = (data.get("feishu_webhook") or "").strip()
    config["feishu_secret"] = (data.get("feishu_secret") or "").strip()
    config["alert_threshold_days"] = threshold
    config["alert_check_interval_hours"] = check_interval
    config["min_alert_interval_hours"] = min_interval
    
    save_alert_config(config)
    return jsonify({"status": "success", "message": "配置已更新"})

@app.post("/api/alert/trigger")
def trigger_alert_now():
    result = perform_alert_check_and_send(force=True)
    status_code = 500 if result["status"] == "error" else 200
    return jsonify(result), status_code

@app.get("/api/alert/ignored")
def get_ignored_app_details():
    config = load_alert_config()
    ignored_app_ids = set(config.get("ignored_app_ids", []))
    if not ignored_app_ids:
        return jsonify([])
    return jsonify(list(ignored_app_ids))

@app.post("/api/alert/ignored")
def add_ignored_app_id():
    data = request.get_json()
    app_id = (data.get("app_id") or "").strip()
    if not app_id: return jsonify({"error": "app_id required"}), 400

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
    config = load_alert_config()
    ignored = config.get("ignored_app_ids", [])
    if app_id in ignored:
        config["ignored_app_ids"] = [x for x in ignored if x != app_id]
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

# === 后台线程 (优化循环) ===
def alert_check_worker():
    print("✅ 告警检查线程已启动")
    while True:
        try:
            result = perform_alert_check_and_send(force=False)
            if result["status"] != "no_alert":
                print(f"🔔 告警检查结果: {result['message']}")
            
            config = load_alert_config()
            interval_hours = config.get("alert_check_interval_hours", 24)
            sleep_seconds = interval_hours * 3600
            
            # 分段休眠以便能更快响应退出
            for _ in range(int(sleep_seconds / 10)):
                time.sleep(10)
        except Exception as e:
            print(f"⚠️ 告警线程异常: {e}")
            time.sleep(300)

if __name__ == "__main__":
    BASE_DIR.joinpath("templates").mkdir(parents=True, exist_ok=True)
    BASE_DIR.joinpath("static").mkdir(parents=True, exist_ok=True)

    alert_thread = threading.Thread(target=alert_check_worker, daemon=True)
    alert_thread.start()

    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=PORT,
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
        threaded=True
    )

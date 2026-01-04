import os
import msal
import requests
import json
import threading
import time
import hmac
import hashlib
import base64
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps

# 加载 .env
load_dotenv()

# === 基础路径配置 ===
BASE_DIR = Path(__file__).resolve().parent

# === 线程锁 ===
CONFIG_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()

# === 环境变量 ===
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "your-client-id")
TENANT_ID = os.getenv("AZURE_TENANT_ID", "your-tenant-id")

_cert_env = os.getenv("CERT_FILE", "app_monitor_cert.pem")
_key_env = os.getenv("KEY_FILE", "app_monitor_key.pem")
CERT_PATH = Path(_cert_env) if Path(_cert_env).is_absolute() else BASE_DIR / _cert_env
KEY_PATH = Path(_key_env) if Path(_key_env).is_absolute() else BASE_DIR / _key_env

DEFAULT_EXPIRY_THRESHOLD_DAYS = int(os.getenv("EXPIRY_THRESHOLD_DAYS", "120"))
DEFAULT_SHOW_APPS_WITHOUT_PASSWORD = os.getenv("SHOW_APPS_WITHOUT_PASSWORD", "1") == "1"
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "300"))
PORT = int(os.getenv("PORT", "8000"))
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")  # 管理员密码，建议通过环境变量设置

ALERT_CONFIG_FILE = BASE_DIR / "alert_config.json"
LAST_ALERTED_FILE = BASE_DIR / "last_alerted.json"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_API_URL = "https://graph.microsoft.com/v1.0/applications"

app = Flask(__name__)
app.secret_key = SECRET_KEY
_MSAL_APP = None

# === 辅助函数 ===
def parse_azure_timestamp(date_str):
    """
    鲁棒地解析 Azure 返回的时间字符串。
    Azure 可能返回 .02, .123 等不固定长度的毫秒，导致 fromisoformat 报错。
    这里直接去掉毫秒部分，只保留秒级精度，并确保时区为 UTC。
    """
    if not date_str:
        return None
    try:
        # 标准化 Z 为 +00:00
        clean_str = date_str.replace("Z", "+00:00")
        # 如果包含小数点（毫秒），直接截断去掉
        if "." in clean_str:
            # split('.')[0] 拿到 YYYY-MM-DDTHH:MM:SS
            # 手动补上 +00:00，因为 Azure 的 Z 时间一定是 UTC
            clean_str = clean_str.split(".")[0] + "+00:00"
        return datetime.fromisoformat(clean_str)
    except Exception as e:
        print(f"Time parse error: {date_str} -> {e}")
        return None

def format_expiry_date(date_value):
    if not date_value: return None
    try:
        if isinstance(date_value, datetime): return date_value.strftime('%Y-%m-%d')
        elif isinstance(date_value, str):
            # 复用上面的解析逻辑，然后再格式化
            dt = parse_azure_timestamp(date_value)
            if dt: return dt.strftime('%Y-%m-%d')
            return date_value[:10]
        return str(date_value)
    except: return str(date_value)

class Cache:
    def __init__(self):
        self._store = {}
        self.ttl = CACHE_TTL_SECONDS
        self.lock = threading.Lock()
    def get(self, params):
        with self.lock:
            if params in self._store:
                ts, data = self._store[params]
                if time.time() - ts < self.ttl: return data, ts
                else: del self._store[params]
        return None, None
    def set(self, params, data):
        with self.lock: self._store[params] = (time.time(), data)

CACHE = Cache()

def load_alert_config():
    if ALERT_CONFIG_FILE.exists():
        try:
            with open(ALERT_CONFIG_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except: pass
    return {}

def save_alert_config(config):
    with CONFIG_LOCK:
        try:
            with open(ALERT_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e: print(f"Save config error: {e}")

def load_last_alerted():
    if LAST_ALERTED_FILE.exists():
        try:
            with open(LAST_ALERTED_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, list): return {} 
                return data
        except: pass
    return {}

def save_last_alerted(data):
    with STATE_LOCK:
        try:
            with open(LAST_ALERTED_FILE, "w") as f: json.dump(data, f)
        except: pass

# === 消息发送 ===
def send_dingtalk_message(webhook, msg, secret=""):
    try:
        ts = str(int(time.time() * 1000))
        url = webhook
        if secret:
            sign_str = f"{ts}\n{secret}"
            hmac_code = hmac.new(secret.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).digest()
            sign = base64.b64encode(hmac_code).decode('utf-8')
            if "access_token=" in webhook:
                url = f"{webhook}&timestamp={ts}&sign={sign}"
        resp = requests.post(url, json={"msgtype": "text", "text": {"content": msg}}, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        print(f"DingTalk Error: {e}")
        return False

def send_feishu_message(webhook, msg, secret=""):
    try:
        ts = str(int(time.time()))
        data = {"msg_type": "text", "content": {"text": msg}}
        if secret:
            sign_str = f"{ts}\n{secret}"
            hmac_code = hmac.new(sign_str.encode("utf-8"), digestmod=hashlib.sha256).digest()
            data.update({"timestamp": ts, "sign": base64.b64encode(hmac_code).decode("utf-8")})
        resp = requests.post(webhook, json=data, timeout=10)
        return resp.status_code == 200 and resp.json().get("code") == 0
    except Exception as e:
        print(f"Feishu Error: {e}")
        return False

# === SMTP Function ===
def send_smtp_message(host, port, user, pwd, to_addr, msg_content):
    try:
        subject = "Azure Credential Expiry Alert"
        
        message = MIMEText(msg_content, 'plain', 'utf-8')
        message['Subject'] = Header(subject, 'utf-8')
        message['From'] = user
        message['To'] = to_addr

        # Determine SSL/TLS based on port
        port = int(port)
        if port == 465:
            # SMTPS (SSL)
            server = smtplib.SMTP_SSL(host, port, timeout=20)
        else:
            # STARTTLS or Plain
            server = smtplib.SMTP(host, port, timeout=20)
            if port == 587:
                server.starttls()
        
        if user and pwd:
            server.login(user, pwd)
            
        server.sendmail(user, [to_addr], message.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"SMTP Error: {e}")
        return False

# === Azure ===
def get_msal_app():
    global _MSAL_APP
    if _MSAL_APP is None:
        with open(CERT_PATH, "rb") as f: cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend()) \
            if b"BEGIN CERTIFICATE" in cert_data else x509.load_der_x509_certificate(cert_data, default_backend())
        thumb = cert.fingerprint(hashes.SHA1()).hex().upper()
        with open(KEY_PATH, "r") as f: key = f.read()
        _MSAL_APP = msal.ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential={"thumbprint": thumb, "private_key": key})
    return _MSAL_APP

def fetch_expiring(days, no_pwd, show_all):
    app_msal = get_msal_app()
    res = app_msal.acquire_token_for_client(scopes=GRAPH_API_SCOPE)
    if "access_token" not in res: 
        global _MSAL_APP
        _MSAL_APP = None
        raise Exception("Token failed")
    
    headers = {"Authorization": f"Bearer {res['access_token']}"}
    cutoff = None if show_all else datetime.now(timezone.utc) + timedelta(days=days)
    url = GRAPH_API_URL
    items = []
    
    while url:
        r = requests.get(url, headers=headers, params={"$select": "id,displayName,appId,passwordCredentials,keyCredentials", "$top": "999"} if url==GRAPH_API_URL else None)
        r.raise_for_status()
        d = r.json()
        for app in d.get("value", []):
            p_creds = app.get("passwordCredentials", [])
            k_creds = app.get("keyCredentials", [])
            if not (p_creds or k_creds) and not no_pwd: continue
            
            for c in p_creds:
                if not c.get("endDateTime"): continue
                # 使用新的解析函数
                dt = parse_azure_timestamp(c["endDateTime"])
                if not dt: continue # 如果解析失败则跳过

                if show_all or (cutoff and dt <= cutoff):
                    items.append({"type": "Client Secret", "app_name": app.get("displayName"), "app_id": app.get("appId"), "cred_name": c.get("displayName"), "expires_on": format_expiry_date(dt)})
            
            for k in k_creds:
                if k.get("usage") != "Verify" or not k.get("endDateTime"): continue
                # 使用新的解析函数
                dt = parse_azure_timestamp(k["endDateTime"])
                if not dt: continue

                if show_all or (cutoff and dt <= cutoff):
                    items.append({"type": "Certificate", "app_name": app.get("displayName"), "app_id": app.get("appId"), "cred_name": k.get("displayName"), "expires_on": format_expiry_date(dt)})
        
        url = d.get("@odata.nextLink")
    
    items.sort(key=lambda x: (0 if x["type"]=="Client Secret" else 1, x["expires_on"]))
    return items

def check_alert(force=False):
    cfg = load_alert_config()
    channel = cfg.get("active_channel", "dingtalk")
    threshold = int(cfg.get("alert_threshold_days", 30))
    min_int = int(cfg.get("min_alert_interval_hours", 24))
    
    try:
        items = fetch_expiring(threshold, True, False)
        ignored = set(cfg.get("ignored_app_ids", []))
        last = load_last_alerted()
        now = datetime.now(timezone.utc)
        alerts = []
        
        for i in items:
            if i["app_id"] in ignored: continue
            key = f"{i['app_id']}|{i['cred_name']}"
            last_ts = last.get(key)
            if not force and last_ts:
                # 解析上次告警时间时也要小心，虽然这里是我们自己存的
                try:
                    last_dt = datetime.fromisoformat(last_ts)
                    if (now - last_dt).total_seconds() < min_int*3600: continue
                except: pass
            alerts.append(i)
            
        if not alerts: return {"status": "no_alert", "message": "No new alerts"}
        
        msg = f"[Azure Expiry Alert]\nFound {len(alerts)} credentials expiring in {threshold} days:\n\n"
        for i in alerts: msg += f"- {i['type']}: {i['app_name']}\n  ID: {i['app_id']}\n  Cred: {i['cred_name']} ({i['expires_on']})\n\n"
        
        logs = []
        
        # === Check Channels ===
        
        # DingTalk Only
        if channel == "dingtalk":
            if cfg.get("dingtalk_webhook"):
                logs.append("DingTalk: " + ("OK" if send_dingtalk_message(cfg["dingtalk_webhook"], msg, cfg.get("dingtalk_secret")) else "Fail"))
        
        # Feishu Only
        elif channel == "feishu":
            if cfg.get("feishu_webhook"):
                logs.append("Feishu: " + ("OK" if send_feishu_message(cfg["feishu_webhook"], msg, cfg.get("feishu_secret")) else "Fail"))
        
        # SMTP (Email) Only
        elif channel == "email":
            if cfg.get("smtp_host") and cfg.get("smtp_to_email"):
                res = send_smtp_message(
                    cfg["smtp_host"], 
                    cfg.get("smtp_port", 25), 
                    cfg.get("smtp_user"), 
                    cfg.get("smtp_password"), 
                    cfg["smtp_to_email"], 
                    msg
                )
                logs.append("SMTP: " + ("OK" if res else "Fail"))

        if any("OK" in l for l in logs):
            for i in alerts: last[f"{i['app_id']}|{i['cred_name']}"] = now.isoformat()
            save_last_alerted(last)
            return {"status": "success", "message": ", ".join(logs)}
        return {"status": "failed", "message": ", ".join(logs) if logs else "No channel active"}
        
    except Exception as e: return {"status": "error", "message": str(e)}

# === 管理员认证装饰器 ===
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({"status": "error", "message": "需要管理员权限"}), 403
        return f(*args, **kwargs)
    return decorated_function

# === Routes ===
@app.get("/")
def index(): return render_template("index.html", default_days=DEFAULT_EXPIRY_THRESHOLD_DAYS, show_without_password=DEFAULT_SHOW_APPS_WITHOUT_PASSWORD, cache_ttl=CACHE_TTL_SECONDS)

@app.get("/admin")
def admin_login_page():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    return render_template("admin_login.html")

@app.post("/admin/login")
def admin_login():
    password = request.json.get("password", "")
    if password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "密码错误"}), 401

@app.post("/admin/logout")
def admin_logout():
    session.pop('admin_logged_in', None)
    return jsonify({"status": "ok"})

@app.get("/admin/dashboard")
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    return render_template("admin.html")

@app.get("/api/expiring")
def api_get():
    days = request.args.get("days", type=int) or DEFAULT_EXPIRY_THRESHOLD_DAYS
    no_pwd = request.args.get("showWithoutPassword") == "true"
    show_all = request.args.get("showAll") == "true"
    key = (days, no_pwd, show_all)
    d, ts = CACHE.get(key)
    if d: return jsonify({"items": d, "cached": True})
    items = fetch_expiring(days, no_pwd, show_all)
    CACHE.set(key, items)
    return jsonify({"items": items, "cached": False})

@app.get("/api/alert/config")
def get_cfg(): return jsonify(load_alert_config())

@app.post("/api/alert/config")
@admin_required
def set_cfg():
    c = load_alert_config()
    d = request.json
    
    # Update regular keys
    fields_to_save = [
        "active_channel", 
        "dingtalk_webhook", "dingtalk_secret", 
        "feishu_webhook", "feishu_secret",
        "smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_to_email"
    ]
    
    c.update({k: d.get(k, "").strip() for k in fields_to_save})
    
    # Update integer keys
    for k in ["alert_threshold_days", "alert_check_interval_hours", "min_alert_interval_hours"]:
        c[k] = int(d.get(k, c.get(k, 24)))
        
    save_alert_config(c)
    return jsonify({"status": "ok"})

@app.post("/api/alert/trigger")
@admin_required
def trigger(): return jsonify(check_alert(True))

@app.get("/api/alert/ignored")
def get_ign():
    ignored_ids = load_alert_config().get("ignored_app_ids", [])
    if not ignored_ids: return jsonify([])
    
    try:
        cache_key = (365, True, True)
        cached_data, _ = CACHE.get(cache_key)
        
        if cached_data:
            all_data = cached_data
        else:
            all_data = fetch_expiring(days=365, no_pwd=True, show_all=True)
            CACHE.set(cache_key, all_data)
    except Exception as e:
        print(f"Error fetching details for ignored list: {e}")
        all_data = []

    result = []
    found_ids = set()

    for item in all_data:
        if item['app_id'] in ignored_ids:
            found_ids.add(item['app_id'])
            result.append(item)
    
    for iid in ignored_ids:
        if iid not in found_ids:
            result.append({
                "app_id": iid,
                "app_name": "(未找到或已删除)",
                "cred_name": "-",
                "type": "未知",
                "expires_on": "-",
                "is_orphan": True 
            })

    result.sort(key=lambda x: x['app_id'])
    return jsonify(result)

@app.post("/api/alert/ignored")
@admin_required
def add_ign():
    c = load_alert_config()
    aid = request.json.get("app_id", "").strip()
    if aid and aid not in c.setdefault("ignored_app_ids", []):
        c["ignored_app_ids"].append(aid)
        save_alert_config(c)
    return jsonify({"status": "ok"})

@app.delete("/api/alert/ignored")
@admin_required
def del_ign():
    c = load_alert_config()
    aid = request.json.get("app_id", "").strip()
    if aid in c.get("ignored_app_ids", []):
        c["ignored_app_ids"].remove(aid)
        save_alert_config(c)
    return jsonify({"status": "ok"})

def worker():
    while True:
        try:
            check_alert(False)
            hrs = int(load_alert_config().get("alert_check_interval_hours", 24))
            for _ in range(hrs * 360): time.sleep(10)
        except: time.sleep(300)

if __name__ == "__main__":
    BASE_DIR.joinpath("templates").mkdir(exist_ok=True)
    threading.Thread(target=worker, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, debug=os.getenv("DEBUG")=="1", threaded=True)

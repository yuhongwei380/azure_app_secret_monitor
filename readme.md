✨ 特性亮点
🔔 智能监控：自动检测 Azure AD 应用凭据（证书）过期情况
⏰ 提前预警：支持自定义过期前天数告警阈值
🔐 安全可靠：使用证书认证而非密码，更安全的 Azure AD 集成
📱 多平台通知：支持企业微信、钉钉、飞书等多种 Webhook 通知
🐳 容器化部署：提供 Docker 和 Docker Compose 一键部署方案
⚙️ 灵活配置：可通过环境变量或配置文件轻松自定义
📊 状态追踪：记录已告警状态，避免重复通知干扰

🚀 快速开始
前提条件
Azure 订阅和全局管理员/应用管理员权限
Python 3.8+ 或 Docker 环境
企业微信/钉钉/飞书等 Webhook 配置（可选）


步骤 1：生成安全证书
```
# 生成 2048 位 RSA 私钥
openssl genrsa -out app_monitor_key.pem 2048

# 创建自签名公钥证书（有效期10年）
openssl req -new -x509 -key app_monitor_key.pem -out app_monitor_cert.pem -days 3650 -subj "/C=CN/ST=Zhejiang/L=Zhejiang/O=company-inc/CN=AppCredentialMonitor"
```


步骤 2：Azure AD 应用配置
注册新应用
登录 Azure Portal
进入 Microsoft Entra ID → 应用注册 → 新注册
名称：App-Credential-Monitor（或自定义）

支持账户类型：仅此组织目录中的账户
1.注册新应用
-登录 Azure Portal
-进入 Microsoft Entra ID → 应用注册 → 新注册
-名称：App-Credential-Monitor（或自定义）
-支持账户类型：仅此组织目录中的账户

2.上传证书
-进入创建的应用 → 证书和密码 → 证书 → 上传证书
-选择生成的 app_monitor_cert.pem 文件
-上传后记录 证书指纹 (Thumbprint) [非必需]

3.配置 API 权限
-进入 API 权限 → 添加权限 → Microsoft Graph
-选择 应用程序权限
-添加：Application.Read.All
-点击 "授予管理员同意"（需要全局/应用管理员）

4.记录关键信息
Application (client) ID
Directory (tenant) ID
```
应用程序(客户端) ID：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
目录(租户) ID：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```
步骤 3：部署与运行
方法一： Python 环境运行
```
# 克隆仓库
git clone https://github.com/yuhongwei380/azure_app_secret_monitor.git
cd azure_app_secret_monitor

# 安装依赖
pip install msal requests cryptography 
pip3 install python-dotenv
pip3 install flask
or
pip install -r requirements.txt

# 配置环境变量
vim .env
# 编辑 .env 文件，填入您的配置信息

# 运行监控器
python3 azure_app_monitor.py
```

方法二：Docker 容器运行

```
# 克隆仓库
git clone https://github.com/yuhongwei380/azure_app_secret_monitor.git
cd azure_app_secret_monitor

# 创建必要的配置文件
touch alert_config.json last_alerted.json

# 编辑 docker-compose.yml，填入您的 client_id 和 tenant_id
vim docker-compose.yml

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f
```

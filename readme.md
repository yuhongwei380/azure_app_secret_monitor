操作步骤
一、生成密钥
```
# 生成私钥
openssl genrsa -out app_monitor_key.pem 2048

# 生成公钥证书（有效期10年）
openssl req -new -x509 -key app_monitor_key.pem -out app_monitor_cert.pem -days 3650
```


二、Azure 配置
```
1.登录 Azure Portal
2.进入 Microsoft Entra ID > 应用注册 > 新注册
    名称：App-Credential-Monitor
    支持账号类型：选“仅此组织目录”
3.创建后，进入该应用
4.左侧菜单：证书和密码 > 证书 > 上传证书
    选择 app_monitor_cert.pem（或 .cer 文件）
    上传成功后，你会看到证书指纹（Thumbprint）
5..授予权限：
    转到 API 权限 > 添加权限 > Microsoft Graph > 应用权限
    添加：Application.Read.All
    点击 “代表管理员授予同意”（需要全局/应用管理员）
6.记下：
Application (client) ID
Directory (tenant) ID
```

三、克隆代码&Python运行
3.1 git clone
```
git clone https://github.com/yuhongwei380/Azure_app_monitor
```
3.2 修改env


3.3 安装运行环境
```
pip install msal requests cryptography 
pip3 install python-dotenv
pip3 install flask
pip install -r requirements.txt
```
3.4 python 本地运行

```
python3 azure_app_monitor.py
```

3.5 Docker运行
<p>需要环境：docker 和docker-compose</p>
<p>需要修改compose.yml中的client ID和Tenant ID</p>

```
touch alert_config.json
touch last_alerted.json
docker-compose up -d
```

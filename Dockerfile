# Dockerfile
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 创建非 root 用户
RUN adduser --disabled-password --gecos '' appuser

# 安装编译依赖（cryptography 需要）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libffi-dev \
        libssl-dev \
        gcc \
    && rm -rf /var/lib/apt/lists/*

# 只复制非敏感文件
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 复制代码（不含 .env 和 .pem）
COPY azure_app_monitor.py .
COPY templates/ templates/
# 如果有 static/ 目录也复制
# COPY static/ static/

# 设置权限
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["python", "azure_app_monitor.py"]

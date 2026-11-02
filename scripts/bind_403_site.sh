#!/bin/bash

set -Eeuo pipefail

# ============================================================
# 将已部署的域名改为监听本地 127.0.0.1:10443 并返回固定 403 响应
# （把公网 443 端口腾出给 Nginx stream 做四层 SNI 分流）
# ============================================================

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
NC="\033[0m"

INTERNAL_HTTPS_PORT="10443"

info() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[×]${NC} $1" >&2
    exit 1
}

if [[ $EUID -ne 0 ]]; then
    error "请使用 root 用户运行此脚本"
fi

for command_name in nginx systemctl ss curl awk grep sed tail cp mv ln readlink \
    date mktemp chmod chown rm; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        error "缺少必要命令：$command_name"
    fi
done

echo
read -rp "请输入已经部署的域名，例如 api.example.com: " DOMAIN

DOMAIN=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]' | xargs)
DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"

if ! [[ "$DOMAIN" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
    error "域名格式不正确：$DOMAIN"
fi

AVAILABLE_DIR="/etc/nginx/sites-available"
ENABLED_DIR="/etc/nginx/sites-enabled"
NGINX_CONF="${AVAILABLE_DIR}/${DOMAIN}"
ENABLED_CONF="${ENABLED_DIR}/${DOMAIN}"

if [[ ! -e "$NGINX_CONF" ]]; then
    error "未找到现有站点配置：$NGINX_CONF"
fi

if [[ -L "$NGINX_CONF" ]]; then
    RESOLVED_CONF=$(readlink -f "$NGINX_CONF")
    if [[ -z "$RESOLVED_CONF" || ! -f "$RESOLVED_CONF" ]]; then
        error "站点配置符号链接无效：$NGINX_CONF"
    fi
    NGINX_CONF="$RESOLVED_CONF"
fi

CERT_PATH=$(awk '
    $1 == "ssl_certificate" {
        value=$2
        sub(/;$/, "", value)
        print value
        exit
    }
' "$NGINX_CONF")

KEY_PATH=$(awk '
    $1 == "ssl_certificate_key" {
        value=$2
        sub(/;$/, "", value)
        print value
        exit
    }
' "$NGINX_CONF")

if [[ -z "$CERT_PATH" ]]; then
    CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
fi

if [[ -z "$KEY_PATH" ]]; then
    KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
fi

if [[ "$CERT_PATH" == *'$'* || "$KEY_PATH" == *'$'* ]]; then
    error "现有配置使用了变量形式的证书路径，无法安全自动迁移"
fi

if [[ ! -f "$CERT_PATH" ]]; then
    error "未找到现有证书：$CERT_PATH"
fi

if [[ ! -f "$KEY_PATH" ]]; then
    error "未找到现有私钥：$KEY_PATH"
fi

info "沿用证书：$CERT_PATH"
info "沿用私钥：$KEY_PATH"

TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
BACKUP_CONF="${NGINX_CONF}.backup-${TIMESTAMP}"
TEMP_CONF=$(mktemp "/tmp/nginx-${DOMAIN}.XXXXXX")

cleanup_temp() {
    rm -f "$TEMP_CONF"
}

trap cleanup_temp EXIT

cp -a "$NGINX_CONF" "$BACKUP_CONF"
info "原配置已备份：$BACKUP_CONF"

cat > "$TEMP_CONF" <<EOF
server {
    listen 80;
    listen [::]:80;

    server_name ${DOMAIN};

    default_type text/plain;
    charset utf-8;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    location / {
        return 403 "请求不合法\n请勿直接访问网络测速API\n";
    }
}

server {
    listen 127.0.0.1:${INTERNAL_HTTPS_PORT} ssl http2;

    server_name ${DOMAIN};

    ssl_certificate ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    default_type text/plain;
    charset utf-8;

    return 403 "请求不合法\n请勿直接访问网络测速API\n";
}
EOF

chmod --reference="$NGINX_CONF" "$TEMP_CONF" 2>/dev/null || chmod 644 "$TEMP_CONF"
chown --reference="$NGINX_CONF" "$TEMP_CONF" 2>/dev/null || true
mv "$TEMP_CONF" "$NGINX_CONF"

ln -sfn "$NGINX_CONF" "$ENABLED_CONF"

rollback() {
    warn "正在恢复原 Nginx 配置..."
    cp -a "$BACKUP_CONF" "$NGINX_CONF"
    ln -sfn "$NGINX_CONF" "$ENABLED_CONF"
    nginx -t >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true
}

info "检测 Nginx 配置..."
if ! nginx -t; then
    rollback
    error "新配置检测失败，已恢复原配置"
fi

info "重启 Nginx..."
if ! systemctl restart nginx; then
    rollback
    error "Nginx 重启失败，已恢复原配置"
fi

if ! ss -lnt | grep -q ":${INTERNAL_HTTPS_PORT}[[:space:]]"; then
    rollback
    error "Nginx 未监听 ${INTERNAL_HTTPS_PORT} 端口，已恢复原配置"
fi

LOCAL_RESPONSE=$(curl -ksS \
    --resolve "${DOMAIN}:${INTERNAL_HTTPS_PORT}:127.0.0.1" \
    -w $'\n%{http_code}' \
    "https://${DOMAIN}:${INTERNAL_HTTPS_PORT}/" || true)

LOCAL_STATUS=$(printf '%s\n' "$LOCAL_RESPONSE" | tail -n 1)
LOCAL_BODY=$(printf '%s\n' "$LOCAL_RESPONSE" | sed '$d')

if [[ "$LOCAL_STATUS" != "403" ]]; then
    rollback
    error "本机 HTTPS 验证未返回 403，已恢复原配置"
fi

EXPECTED_BODY=$'请求不合法\n请勿直接访问网络测速API'

if [[ "$LOCAL_BODY" != "$EXPECTED_BODY" ]]; then
    rollback
    error "本机 HTTPS 响应正文不符合预期，已恢复原配置"
fi

echo
echo "============================================================"
echo -e "${GREEN}站点配置迁移完成！${NC}"
echo " 域名：         $DOMAIN"
echo " 内部监听端口： 127.0.0.1:${INTERNAL_HTTPS_PORT}"
echo " HTTP状态：     403 Forbidden"
echo " 原配置备份：   $BACKUP_CONF"
echo "============================================================"

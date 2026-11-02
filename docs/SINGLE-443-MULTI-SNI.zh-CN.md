# 单 443 端口 + 多 SNI 域名 + relaynode 转发多台 v2node 落地机 部署与运维文档

这是一份为你当前环境量身定制的 **「单 443 端口 + 多 SNI 域名 + relaynode 转发多台 v2node 落地机」** 完整部署与运维文档。文档中已将你原有的自动化建站脚本同步改造为适配 `10443` 内部回源端口的版本，避免与 Nginx `stream` 争抢 `443` 端口。

---

## 一、 架构设计与端口规划总览

在中转机（服务器 A）上，所有外部代理流量和浏览器/探测器访问统一由公网 `443` 端口进入，内部各组件端口分工如下：

| 组件名称 | 监听地址与端口 | 承担角色与流向说明 |
| :--- | :--- | :--- |
| **Nginx stream 模块** | `0.0.0.0:443`、`[::]:443` | **公网总入口**：读取 TLS 握手中的 SNI 域名，将外部请求分发给本机 relaynode 不同端口；将落地机回源请求直接转给本机 `10443` 真实网站。 |
| **Nginx http 站点** | `127.0.0.1:10443` | **本地真实 HTTPS 网站**：绑定所有 SNI 域名的真实 SSL 证书，固定返回 `403 请求不合法 / 请勿直接访问网络测速API`。 |
| **Nginx http (80)** | `0.0.0.0:80`、`[::]:80` | 保持公网开放，用于 ACME / Let's Encrypt 证书自动续期及返回 403。 |
| **relaynode 规则 1** | `127.0.0.1:8443`（或 `0.0.0.0:8443`） | 接收 `de01` 域名流量，四层转发至 **落地机 1 (v2node)**。 |
| **relaynode 规则 2** | `127.0.0.1:7443`（或 `0.0.0.0:7443`） | 接收 `de02` 域名流量，四层转发至 **落地机 2 (v2node)**。 |
| **relaynode 规则 3** | `127.0.0.1:6443`（或 `0.0.0.0:6443`） | 接收 `de03` 域名流量，四层转发至 **落地机 3 (v2node)**。 |

---

## 二、 第一步：准备中转机 Nginx stream 模块环境

在 Debian / Ubuntu 系统中，首先需要确认 Nginx 已加载四层 `stream` 模块：

```bash
# 1. 检查是否已包含 stream_ssl_preread 模块
nginx -V 2>&1 | grep with-stream_ssl_preread_module

# 2. 如果未安装动态模块，执行以下命令安装（Debian/Ubuntu）：
apt update && apt install -y libnginx-mod-stream
```

> **注：** 安装 `libnginx-mod-stream` 后，系统会自动在 `/etc/nginx/modules-enabled/` 下创建模块加载配置，无需手动写 `load_module`。

---

## 三、 第二步：使用改造后的脚本绑定各 SNI 域名（监听 10443）

因为公网 `443` 端口要留给 Nginx `stream` 做分流，本地 HTTPS 网站需要改为监听 `127.0.0.1:10443`（否则两者都监听 443 会报端口占用冲突）。

将以下改造后的脚本保存为 `/root/bind_403_site.sh`（已修复不可见空格字符、保留 80 端口续期目录，并将 HTTPS 站点端口改为 `127.0.0.1:10443`）：

```bash
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
```

> **注意：** 请确保 `/etc/nginx/sites-enabled/` 目录下的所有站点配置文件都已经把 `listen 443` 改为了 `listen 127.0.0.1:10443`，确保没有任何一个 `http` 站点还占用着 `443` 端口。

---

## 四、 第三步：配置 Nginx stream 接管公网 443 端口

打开中转机的 `/etc/nginx/nginx.conf`，在文件最底部（**必须在 `http { ... }` 块的外面**）添加以下 `stream` 块配置：

```nginx
stream {
    # 1. 根据客户端请求的 SNI 域名，分发到本机 relaynode 对应的转发端口
    map $ssl_preread_server_name $sni_relay_pool {
        region-de01-speedtestapi.howfastyourspeed.com    127.0.0.1:8443;
        region-de02-speedtestapi.howfastyourspeed.com    127.0.0.1:7443;
        region-de03-speedtestapi.howfastyourspeed.com    127.0.0.1:6443;
        region-de04-speedtestapi.howfastyourspeed.com    127.0.0.1:5443;
        # 未知域名或直接用 IP 扫描时，直接丢给本机真实网站返回 403/证书拒绝
        default                                          127.0.0.1:10443;
    }

    # 2. 防回落死循环白名单：
    # 当落地机上的 v2node 触发 REALITY 回落访问中转机 443 时，
    # 识别出落地机 IP，直接导入本机 127.0.0.1:10443 真实网站，不再经过 relaynode
    geo $final_backend {
        default              $sni_relay_pool;

        # 下面填入你所有落地机的公网 IPv4（及 IPv6，如有）地址：
        11.22.33.44/32       127.0.0.1:10443;   # 落地机 1 (de01) 的公网 IP
        55.66.77.88/32       127.0.0.1:10443;   # 落地机 2 (de02) 的公网 IP
        99.88.77.66/32       127.0.0.1:10443;   # 落地机 3 (de03) 的公网 IP
        127.0.0.1/32         127.0.0.1:10443;   # 本机回环测试直接进真实网站
    }

    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;

        ssl_preread on;
        proxy_pass $final_backend;

        proxy_connect_timeout 10s;
        proxy_timeout 300s;
    }
}
```

保存后测试并重载 Nginx：

```bash
nginx -t && systemctl reload nginx
```

---

## 五、 第四步：relay-panel 与机场面板 (v2node) 参数对齐

### 1. relay-panel（relaynode）规则设置

保持你现有的端口转发规则不变：
- **规则 1：** 中转监听端口 `8443` ➔ 转发至 `落地机1_IP:8443`
- **规则 2：** 中转监听端口 `7443` ➔ 转发至 `落地机2_IP:7443`
- **规则 3：** 中转监听端口 `6443` ➔ 转发至 `落地机3_IP:6443`

### 2. 机场面板 (v2node) 节点配置表

对照你之前的面板配置界面，按以下标准填写每个节点：

| 面板字段名称 | 落地机 1 (de01) 填写内容 | 落地机 2 (de02) 填写内容 | 关键说明 |
| :--- | :--- | :--- | :--- |
| **连接地址** | `region-de01-speedtestapi.howfastyourspeed.com` | `region-de02-speedtestapi.howfastyourspeed.com` | 直接填对应的 SNI 域名（确保该域名 A 记录解析在中转机 IP 上，消除 DNS 与 SNI 不一致特征） |
| **监听地址** | `0.0.0.0` | `0.0.0.0` | 保持默认 |
| **连接端口** | `443` | `443` | 所有节点统一填 `443`（客户端连接中转机的 443） |
| **服务端口** | `8443` | `7443` | 填落地机上 v2node 实际监听的端口（与 relaynode 转发的目标端口一致） |
| **节点协议 / 安全性** | `VLess / Reality` | `VLess / Reality` | 点击「安全性 -> 编辑配置」进入子菜单 |
| **↳ Server Name(SNI)** | `region-de01-speedtestapi.howfastyourspeed.com` | `region-de02-speedtestapi.howfastyourspeed.com` | 必须与连接地址及中转机 Nginx 证书域名一致 |
| **↳ Server Address** | 留空（或填中转机 IPv4） | 留空（或填中转机 IPv4） | 默认使用 SNI 解析回中转机 |
| **↳ Server Port** | `443` | `443` | 落地机回源连中转机的 443，会被中转机 `geo` 白名单自动导入 `10443` |
| **↳ Proxy Protocol** | `0` | `0` | 保持为 `0` |

---

## 六、 日常扩容 SOP：以后每新增一台落地机怎么做？

后续如果你要加第 4 台、第 5 台落地机，只需按顺序执行以下 4 步：

1. **解析域名并申请证书：** 将新域名（如 `region-de05-...`）解析到中转机 IP，签发证书后运行 `/root/bind_403_site.sh` 生成 `127.0.0.1:10443` 站点配置。
2. **添加 relay-panel 规则：** 在 relay-panel 新增一个中转端口（如 `4443`）转发到新落地机。
3. **更新 `nginx.conf` 的 `stream` 块：**
   - 在 `map $ssl_preread_server_name` 中加一行：`region-de05-... 127.0.0.1:4443;`
   - 在 `geo $final_backend` 中加一行：`新落地机IP/32 127.0.0.1:10443;`
   - 运行 `nginx -t && systemctl reload nginx`。
4. **在机场面板添加节点：** 连接端口填 `443`，服务端口填 `4443`，SNI 填 `region-de05-...`，Server Port 填 `443`。

---

## 七、 验收测试与排错命令速查

部署完成后，依次执行以下 3 条命令即可确认全链路正常：

1. **在中转机本地测试内部 `10443` 站点是否正常响应：**
   ```bash
   curl -v --resolve "region-de01-speedtestapi.howfastyourspeed.com:10443:127.0.0.1" https://region-de01-speedtestapi.howfastyourspeed.com:10443/
   ```

2. **在落地机上测试回源中转机 `443` 是否命中 `geo` 白名单（无死循环）：**
   ```bash
   curl -v https://region-de01-speedtestapi.howfastyourspeed.com:443/
   ```
   > 若秒回 `HTTP/2 403` 及 `请求不合法`，说明落地机 IP 已正确写入 `geo` 白名单。若卡住超时，说明落地机公网 IP 未加入 `geo` 块，或走了 IPv6 地址，用 `curl -4 ifconfig.me` 和 `curl -6 ifconfig.me` 查看落地机出口 IP 并补入 `geo` 即可。

3. **在外部电脑（或浏览器）直接访问标准 HTTPS 链接（无需带端口号）：**
   - https://region-de01-speedtestapi.howfastyourspeed.com/
   - https://region-de02-speedtestapi.howfastyourspeed.com/
   > 所有域名均在标准 `443` 端口返回有效证书与 `403` 页面，同时客户端连接 `443` 端口按各自域名精准分流至对应落地机。

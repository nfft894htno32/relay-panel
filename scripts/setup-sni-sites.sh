#!/usr/bin/env bash

set -Eeuo pipefail

# ==============================================================================
# 多域名 Cloudflare DNS + acme.sh SSL 证书 + Nginx 200 测速伪装站一键部署脚本
# （100% 兼容原有 acme.sh 单域名脚本，支持自动接管/迁移旧域名并释放公网 443 端口）
# ==============================================================================

# 可选固定配置（公开仓库保持为空即可；若为空，脚本会自动读取 /root/.acme.sh/account.conf 已存 Token 或交互提示输入）
CF_API_TOKEN="${CF_API_TOKEN:-}"

# Cloudflare 是否开启小云朵代理（中转直连必须为 false）
CF_PROXIED=false

# ==============================================================================
# 基础输出函数
# ==============================================================================
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
NC="\033[0m"

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[×]${NC} $*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
    error "请使用 root 用户运行此脚本"
fi

# ==============================================================================
# 1. 安装基础组件（与原脚本保持完全一致，使用 acme.sh，不混用 certbot）
# ==============================================================================
ensure_dependencies() {
    local missing=()
    command -v nginx >/dev/null 2>&1   || missing+=("nginx")
    command -v curl >/dev/null 2>&1    || missing+=("curl")
    command -v jq >/dev/null 2>&1      || missing+=("jq")
    command -v openssl >/dev/null 2>&1 || missing+=("openssl")
    command -v crontab >/dev/null 2>&1 || missing+=("cron")
    command -v ss >/dev/null 2>&1      || missing+=("iproute2")

    if (( ${#missing[@]} > 0 )); then
        info "安装缺失组件：${missing[*]} ..."
        apt-get update -y -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            nginx curl jq ca-certificates openssl cron iproute2
    fi

    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl enable --now cron >/dev/null 2>&1 || true
}

nginx_supports_http2_directive() {
    local ver major minor patch
    ver=$(nginx -v 2>&1 | sed -nE 's/.*nginx\/([0-9]+)\.([0-9]+)\.([0-9]+).*/\1 \2 \3/p')
    [[ -z "$ver" ]] && return 1
    read -r major minor patch <<< "$ver"
    if (( major > 1 )) || (( major == 1 && minor > 25 )) || (( major == 1 && minor == 25 && patch >= 1 )); then
        return 0
    fi
    return 1
}

ensure_dependencies

echo
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  多域名 acme.sh 证书 + 网络测速伪装站 (HTTP 200) 部署工具  ${NC}"
echo -e "${CYAN}============================================================${NC}"
echo

# ==============================================================================
# 2. 输入多域名 & 选择监听模式 & 检测旧版占用 443 的站点
# ==============================================================================
read -rp "请输入要配置的域名（多个域名用空格或逗号分隔，如 de01.example.com de02.example.com）: " RAW_DOMAINS

RAW_DOMAINS="${RAW_DOMAINS//,/ }"
declare -a DOMAINS=()
declare -A SEEN_DOMAINS=()

add_domain() {
    local d="$1"
    d=$(echo "$d" | tr '[:upper:]' '[:lower:]' | xargs)
    d="${d#http://}"
    d="${d#https://}"
    d="${d%%/*}"
    [[ -z "$d" ]] && return 0

    if ! [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
        error "域名格式不正确：$d"
    fi

    if [[ -z "${SEEN_DOMAINS[$d]:-}" ]]; then
        SEEN_DOMAINS[$d]=1
        DOMAINS+=("$d")
    fi
}

for item in $RAW_DOMAINS; do
    add_domain "$item"
done

echo
echo "请选择 Nginx HTTPS 监听模式："
echo "  1) 本地回源模式 127.0.0.1:10443 （推荐：将公网 443 腾给 relay-node 多 SNI 分流）"
echo "  2) 公网直连模式 0.0.0.0:443 & [::]:443 （Nginx 直接监听公网 443）"
read -rp "请输入选项 [1/2，默认 1]: " LISTEN_MODE
LISTEN_MODE="${LISTEN_MODE:-1}"

INTERNAL_HTTPS_PORT="10443"
if [[ "$LISTEN_MODE" == "1" ]]; then
    read -rp "请输入本地 HTTPS 回源监听端口 [默认 10443]: " INPUT_PORT
    INTERNAL_HTTPS_PORT="${INPUT_PORT:-10443}"
    if ! [[ "$INTERNAL_HTTPS_PORT" =~ ^[0-9]+$ ]] || (( INTERNAL_HTTPS_PORT < 1 || INTERNAL_HTTPS_PORT > 65535 )); then
        error "端口号无效：$INTERNAL_HTTPS_PORT"
    fi
    VERIFY_PORT="$INTERNAL_HTTPS_PORT"
    LISTEN_SUMMARY="127.0.0.1:${INTERNAL_HTTPS_PORT}"
elif [[ "$LISTEN_MODE" == "2" ]]; then
    VERIFY_PORT="443"
    LISTEN_SUMMARY="0.0.0.0:443, [::]:443"
else
    error "无效的监听模式选项：$LISTEN_MODE"
fi

echo
read -rp "是否将本机公网 IP 添加到 Cloudflare DNS A 记录？（入口中转机选 Y；后端落地机选 n 仅签证书不暴露落地 IP）[Y/n]: " UPDATE_DNS_A
UPDATE_DNS_A="${UPDATE_DNS_A:-Y}"

AVAILABLE_DIR="/etc/nginx/sites-available"
ENABLED_DIR="/etc/nginx/sites-enabled"
mkdir -p "$AVAILABLE_DIR" "$ENABLED_DIR"

if (( ${#DOMAINS[@]} == 0 )); then
    error "未输入任何有效域名"
fi

info "本次仅部署您指定的 ${#DOMAINS[@]} 个域名（自动忽略并停用未在列表中的旧站点）：${DOMAINS[*]}"

# 清理此前如果误装了 certbot 可能留在系统里的定时器
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^certbot\.timer'; then
    systemctl disable --now certbot.timer >/dev/null 2>&1 || true
fi

# ==============================================================================
# 3. 读取 / 校验 Cloudflare API Token（自动兼容 acme.sh 已保存的 Token！）
# ==============================================================================
ACME_HOME="/root/.acme.sh"
ACME_SH="${ACME_HOME}/acme.sh"
ACME_ACCOUNT_CONF="${ACME_HOME}/account.conf"
CF_CRED_BACKUP="/etc/letsencrypt/cloudflare.ini"

if [[ -z "$CF_API_TOKEN" || "$CF_API_TOKEN" == "这里填写你的Cloudflare_API_Token" ]]; then
    CF_API_TOKEN=""
    # 1. 优先从原脚本 acme.sh 的 account.conf 自动提取 SAVED_CF_Token
    if [[ -f "$ACME_ACCOUNT_CONF" ]]; then
        CF_API_TOKEN=$(awk -F'=' '/^SAVED_CF_Token=/ {v=$2; gsub(/^[\x27"]|[\x27"]$/, "", v); gsub(/[[:space:]]/, "", v); print v; exit}' "$ACME_ACCOUNT_CONF" || true)
    fi
    # 2. 其次尝试读取 /etc/letsencrypt/cloudflare.ini
    if [[ -z "$CF_API_TOKEN" && -f "$CF_CRED_BACKUP" ]]; then
        CF_API_TOKEN=$(awk -F'=' '/dns_cloudflare_api_token/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$CF_CRED_BACKUP" || true)
    fi

    if [[ -n "$CF_API_TOKEN" ]]; then
        echo
        read -rp "检测到本机已保存的 Cloudflare API Token，是否直接沿用？[Y/n]: " USE_SAVED_CF
        USE_SAVED_CF="${USE_SAVED_CF:-Y}"
        if ! [[ "$USE_SAVED_CF" =~ ^[Yy]$ ]]; then
            CF_API_TOKEN=""
        fi
    fi

    if [[ -z "$CF_API_TOKEN" ]]; then
        echo
        read -rsp "请输入 Cloudflare API Token（需 Zone:Read + DNS:Edit 权限，输入不回显）: " CF_API_TOKEN
        echo
        CF_API_TOKEN=$(echo "$CF_API_TOKEN" | xargs)
    fi
fi

NEED_CF_API=1
cert_is_valid_30d() {
    local cert_file="$1"
    [[ -f "$cert_file" ]] && openssl x509 -in "$cert_file" -noout -checkend 2592000 >/dev/null 2>&1
}

CF_API="https://api.cloudflare.com/client/v4"
CF_AUTH_HEADER=(
    -H "Authorization: Bearer ${CF_API_TOKEN}"
    -H "Content-Type: application/json"
)

if (( NEED_CF_API == 1 )); then
    if [[ -z "$CF_API_TOKEN" ]]; then
        error "Cloudflare API Token 不能为空"
    fi
    info "正在验证 Cloudflare API Token ..."
    CF_VERIFY=$(curl -fsS "${CF_AUTH_HEADER[@]}" "${CF_API}/zones?per_page=1" 2>/dev/null || true)
    if [[ "$(echo "$CF_VERIFY" | jq -r '.success // false' 2>/dev/null)" != "true" ]]; then
        error "Cloudflare API Token 验证失败，请检查权限（Zone -> Zone -> Read, Zone -> DNS -> Edit）"
    fi
    info "Cloudflare API Token 验证通过"
fi

# ==============================================================================
# 4. 获取服务器公网 IPv4 并在 Cloudflare 新增 A 记录（保留其他同名 A 记录不动）
# ==============================================================================
declare -A ZONE_CACHE=()
declare -A DOMAIN_ZONE_ID=()

find_zone_id() {
    local domain="$1"
    local current="$domain"
    while [[ "$current" == *.* ]]; do
        if [[ -n "${ZONE_CACHE[$current]:-}" ]]; then
            echo "${ZONE_CACHE[$current]}"
            return 0
        fi
        local resp found_id
        resp=$(curl -fsS "${CF_AUTH_HEADER[@]}" "${CF_API}/zones?name=${current}&status=active" 2>/dev/null || true)
        found_id=$(echo "$resp" | jq -r '.result[0].id // empty' 2>/dev/null || true)
        if [[ -n "$found_id" ]]; then
            ZONE_CACHE[$current]="$found_id"
            echo "$found_id"
            return 0
        fi
        current="${current#*.}"
    done
    return 1
}

if (( NEED_CF_API == 1 )); then
    if [[ "$UPDATE_DNS_A" =~ ^[Yy]$ ]]; then
        info "获取服务器公网 IPv4..."
        SERVER_IP=""
        for ip_url in "https://api.ipify.org" "https://api4.ipify.org" "https://ipv4.icanhazip.com"; do
            SERVER_IP=$(curl -4 -fsS --max-time 10 "$ip_url" 2>/dev/null | xargs || true)
            [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && break
        done

        if ! [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            error "无法获取服务器公网 IPv4"
        fi
        info "服务器公网 IP：$SERVER_IP"

        for domain in "${DOMAINS[@]}"; do
            zone_id=$(find_zone_id "$domain" || true)
            if [[ -z "$zone_id" ]]; then
                error "无法找到域名 ${domain} 对应的 Cloudflare Zone，请检查域名是否已接入 Cloudflare"
            fi
            DOMAIN_ZONE_ID[$domain]="$zone_id"

            # 完全沿用您原脚本逻辑：仅当当前服务器 IP 的 A 记录不存在时新增，绝不覆盖其他同名 A 记录
            dns_resp=$(curl -fsS "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${zone_id}/dns_records?type=A&name=${domain}")
            if [[ "$(echo "$dns_resp" | jq -r '.success')" != "true" ]]; then
                echo "$dns_resp" | jq . >&2 || true
                error "[${domain}] Cloudflare DNS 记录查询失败"
            fi

            current_ip_record_id=$(echo "$dns_resp" | jq -r --arg ip "$SERVER_IP" 'first(.result[]? | select(.content == $ip) | .id) // empty')
            if [[ -n "$current_ip_record_id" ]]; then
                info "[${domain}] 当前服务器 IP (${SERVER_IP}) 的 A 记录已存在，跳过重复新增"
            else
                dns_data=$(jq -n \
                    --arg type "A" \
                    --arg name "$domain" \
                    --arg content "$SERVER_IP" \
                    --argjson proxied "$CF_PROXIED" \
                    '{type: $type, name: $name, content: $content, ttl: 60, proxied: $proxied}')

                result=$(curl -fsS -X POST "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${zone_id}/dns_records" --data "$dns_data")
                if [[ "$(echo "$result" | jq -r '.success')" != "true" ]]; then
                    echo "$result" | jq . >&2 || true
                    error "[${domain}] Cloudflare DNS A 记录新增失败"
                fi
                info "[${domain}] DNS A 记录新增成功 -> ${SERVER_IP}（其他同名 A 记录全部保留）"
            fi
        done
    else
        info "已跳过 Cloudflare DNS A 记录写入（仅使用 DNS TXT 验证签发证书，不暴露本机 IP）"
    fi
fi

# ==============================================================================
# 5. 安装 acme.sh 并按需签发 / 沿用 SSL 证书
# ==============================================================================
ensure_acme_sh() {
    local installer="/tmp/acme-install.sh"
    if [[ ! -x "$ACME_SH" || ! -f "${ACME_HOME}/dnsapi/dns_cf.sh" ]]; then
        info "安装 acme.sh..."
        if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 120 \
            https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o "$installer"; then
            error "acme.sh 下载失败，请检查服务器是否能访问 raw.githubusercontent.com"
        fi
        chmod 700 "$installer"
        sh "$installer" --install-online --home "$ACME_HOME" --config-home "$ACME_HOME" --nocron --noprofile
        rm -f "$installer"
    fi
    chmod 700 "$ACME_HOME"
    "$ACME_SH" --install-cronjob --home "$ACME_HOME" --config-home "$ACME_HOME" >/dev/null
}

declare -A DOMAIN_CERT=()
declare -A DOMAIN_KEY=()

for domain in "${DOMAINS[@]}"; do
    existing_conf="${AVAILABLE_DIR}/${domain}"
    [[ -L "$existing_conf" ]] && existing_conf=$(readlink -f "$existing_conf" || echo "$existing_conf")

    cert_path=""
    key_path=""

    # 优先读取现有 Nginx 配置中的证书路径
    if [[ -f "$existing_conf" ]]; then
        cert_path=$(awk '$1 == "ssl_certificate" { v=$2; sub(/;$/, "", v); print v; exit }' "$existing_conf" || true)
        key_path=$(awk '$1 == "ssl_certificate_key" { v=$2; sub(/;$/, "", v); print v; exit }' "$existing_conf" || true)
        if [[ "$cert_path" == *'$'* || "$key_path" == *'$'* ]]; then
            cert_path=""
            key_path=""
        fi
    fi

    if [[ -z "$cert_path" || ! -f "$cert_path" ]]; then
        cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
        key_path="/etc/letsencrypt/live/${domain}/privkey.pem"
    fi

    # 若证书已存在且剩余有效期 > 30 天，直接沿用，无需重复申请，彻底避免冲突！
    if [[ -f "$cert_path" && -f "$key_path" ]] && cert_is_valid_30d "$cert_path"; then
        info "[${domain}] 检测到有效现有证书（剩余 >30 天），直接沿用：${cert_path}"
        DOMAIN_CERT[$domain]="$cert_path"
        DOMAIN_KEY[$domain]="$key_path"
        continue
    fi

    # 需要用 acme.sh 签发新证书
    ensure_acme_sh

    zone_id="${DOMAIN_ZONE_ID[$domain]:-}"
    if [[ -z "$zone_id" ]]; then
        zone_id=$(find_zone_id "$domain" || true)
    fi
    if [[ -z "$zone_id" ]]; then
        error "[${domain}] 无法获取 Cloudflare Zone ID，无法签发证书"
    fi

    info "[${domain}] 正在通过 acme.sh (Cloudflare DNS) 申请 Let's Encrypt ECC 证书..."
    export CF_Token="$CF_API_TOKEN"
    export CF_Zone_ID="$zone_id"

    set +e
    "$ACME_SH" --issue \
        --home "$ACME_HOME" \
        --config-home "$ACME_HOME" \
        --server letsencrypt \
        --dns dns_cf \
        --dnssleep 20 \
        --keylength ec-256 \
        -d "$domain"
    acme_rc=$?
    set -e

    if [[ "$acme_rc" -ne 0 && "$acme_rc" -ne 2 ]]; then
        unset CF_Token CF_Zone_ID
        error "[${domain}] Let's Encrypt SSL 证书申请失败（退出码 ${acme_rc}）"
    fi

    # 若之前 certbot 创建过同名符号链接目录，清理该子目录内的残留软链后再由 acme.sh 写入实体文件
    cert_dir="/etc/letsencrypt/live/${domain}"
    mkdir -p "$cert_dir"
    chmod 700 "$cert_dir"
    cert_path="${cert_dir}/fullchain.pem"
    key_path="${cert_dir}/privkey.pem"
    [[ -L "$cert_path" ]] && rm -f "$cert_path"
    [[ -L "$key_path" ]]  && rm -f "$key_path"

    rm -f "/usr/local/sbin/sync-${domain}-tls-to-v2node.sh"
    rm -f "/etc/letsencrypt/renewal-hooks/deploy/sync-${domain}-tls-to-v2node.sh"

    if ! "$ACME_SH" --install-cert \
        --home "$ACME_HOME" \
        --config-home "$ACME_HOME" \
        --ecc \
        -d "$domain" \
        --key-file "$key_path" \
        --fullchain-file "$cert_path" \
        --reloadcmd "systemctl is-active --quiet nginx && systemctl reload nginx || true"; then
        unset CF_Token CF_Zone_ID
        error "[${domain}] SSL 证书安装到 ${cert_dir} 失败"
    fi

    unset CF_Token CF_Zone_ID
    chmod 600 "$key_path"
    chmod 644 "$cert_path"

    DOMAIN_CERT[$domain]="$cert_path"
    DOMAIN_KEY[$domain]="$key_path"
    info "[${domain}] SSL 证书申请并安装成功"
done

# ==============================================================================
# 6. 生成 HTTP 200 零刷流风险伪装网络监测网页 (/var/www/edge-speedtest)
#    仅开放 <1KB 的真实 RTT 延迟 / 抖动 / 连续性探测，物理移除大体积测速块，彻底防刷流量
# ==============================================================================
WEB_ROOT="/var/www/edge-speedtest"
mkdir -p "$WEB_ROOT"
chmod 755 /var /var/www "$WEB_ROOT"

# 确保移除旧版可能留下的测速载荷大文件
rm -f "${WEB_ROOT}/chunk.bin"

cat > "${WEB_ROOT}/index.html" <<'HTML_EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Edge Network Quality & Telemetry Node</title>
<style>
  :root {
    --bg: #0b1020;
    --card: #131b33;
    --border: rgba(255, 255, 255, 0.08);
    --text: #e8eefc;
    --muted: #8ea0c8;
    --accent: #3b82f6;
    --accent-glow: rgba(59, 130, 246, 0.35);
    --ok: #10b981;
    --warn: #f59e0b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
    background: radial-gradient(circle at 50% 0%, #172554 0%, var(--bg) 65%);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .container {
    width: 100%;
    max-width: 720px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 32px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
  }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 28px;
    gap: 12px;
    flex-wrap: wrap;
  }
  .title-group h1 { font-size: 20px; font-weight: 600; letter-spacing: 0.3px; }
  .title-group p { font-size: 13px; color: var(--muted); margin-top: 4px; }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--ok);
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.25);
    padding: 6px 12px;
    border-radius: 999px;
  }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); box-shadow: 0 0 8px var(--ok); }
  .metrics {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }
  @media (max-width: 560px) { .metrics { grid-template-columns: 1fr; } }
  .metric-box {
    background: rgba(255, 255, 255, 0.025);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px;
    text-align: center;
  }
  .metric-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; }
  .metric-value { font-size: 28px; font-weight: 700; margin: 8px 0 4px; font-variant-numeric: tabular-nums; }
  .metric-unit { font-size: 12px; color: var(--muted); }
  .progress-wrap {
    height: 8px;
    background: rgba(255, 255, 255, 0.06);
    border-radius: 999px;
    overflow: hidden;
    margin-bottom: 20px;
  }
  .progress-bar {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, #3b82f6, #06b6d4);
    transition: width 0.2s ease;
  }
  .notice {
    display: none;
    font-size: 13px;
    color: var(--warn);
    background: rgba(245, 158, 11, 0.08);
    border: 1px solid rgba(245, 158, 11, 0.22);
    border-radius: 10px;
    padding: 10px 14px;
    margin-bottom: 20px;
    text-align: center;
  }
  .actions { display: flex; justify-content: center; gap: 12px; flex-wrap: wrap; }
  button {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 12px;
    padding: 12px 30px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 8px 24px var(--accent-glow);
    transition: transform 0.15s ease, opacity 0.15s ease;
  }
  button.secondary {
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid var(--border);
    box-shadow: none;
    color: var(--muted);
  }
  button:hover:not(:disabled) { transform: translateY(-1px); }
  button:disabled { opacity: 0.55; cursor: not-allowed; }
  .footer {
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: var(--muted);
    flex-wrap: wrap;
    gap: 8px;
  }
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title-group">
        <h1>边缘节点网络质量监测台</h1>
        <p id="nodeHost">正在识别接入点...</p>
      </div>
      <div class="badge"><span class="dot"></span> 节点在线 (200 OK)</div>
    </div>

    <div class="metrics">
      <div class="metric-box">
        <div class="metric-label">往返延迟 (RTT)</div>
        <div class="metric-value" id="pingVal">--</div>
        <div class="metric-unit">ms</div>
      </div>
      <div class="metric-box">
        <div class="metric-label">网络抖动 (Jitter)</div>
        <div class="metric-value" id="jitterVal">--</div>
        <div class="metric-unit">ms</div>
      </div>
      <div class="metric-box">
        <div class="metric-label">探测可达率 (Reachability)</div>
        <div class="metric-value" id="lossVal">--</div>
        <div class="metric-unit">%</div>
      </div>
    </div>

    <div class="progress-wrap"><div class="progress-bar" id="bar"></div></div>
    <div class="notice" id="authNotice"></div>

    <div class="actions">
      <button id="startBtn" onclick="runPingTest()">开始延迟与抖动探测</button>
      <button class="secondary" onclick="promptThroughput()">吞吐压测 (需运维授权)</button>
    </div>

    <div class="footer">
      <span id="protoInfo">协议：TLS / HTTP</span>
      <span id="statusText">就绪 · 公开模式开放轻量级无损延迟探测</span>
    </div>
  </div>

<script>
  document.getElementById('nodeHost').textContent = '接入节点：' + window.location.hostname;
  document.getElementById('protoInfo').textContent = '安全传输：' + window.location.protocol.replace(':', '').toUpperCase();

  function promptThroughput() {
    const notice = document.getElementById('authNotice');
    const token = window.prompt('请输入节点运维压测口令 ( Ops Authorization Token )：');
    if (token === null) return;
    notice.style.display = 'block';
    notice.textContent = '[安全策略拦截] 运维口令校验未通过：当前公共探针仅开放无损 RTT 延迟探测，已拒绝大流量吞吐压测请求。';
  }

  async function runPingTest() {
    const btn = document.getElementById('startBtn');
    const bar = document.getElementById('bar');
    const status = document.getElementById('statusText');
    const notice = document.getElementById('authNotice');
    notice.style.display = 'none';
    btn.disabled = true;
    bar.style.width = '8%';

    try {
      status.textContent = '正在执行边缘节点多轮 HTTP/TLS 握手与 RTT 采样...';
      const samples = [];
      let okCount = 0;
      const total = 8;

      for (let i = 0; i < total; i++) {
        const t0 = performance.now();
        const res = await fetch('/api/ping?t=' + Date.now() + '_' + i, { cache: 'no-store' });
        const rtt = performance.now() - t0;
        if (res.ok) {
          okCount++;
          if (i > 0) samples.push(rtt);
        }
        bar.style.width = Math.round(((i + 1) / total) * 100) + '%';
      }

      if (samples.length > 0) {
        const avgPing = samples.reduce((a, b) => a + b, 0) / samples.length;
        let jitterSum = 0;
        for (let i = 1; i < samples.length; i++) jitterSum += Math.abs(samples[i] - samples[i - 1]);
        const jitter = samples.length > 1 ? jitterSum / (samples.length - 1) : 0;

        document.getElementById('pingVal').textContent = avgPing.toFixed(1);
        document.getElementById('jitterVal').textContent = jitter.toFixed(1);
      }
      document.getElementById('lossVal').textContent = Math.round((okCount / total) * 100).toString();
      status.textContent = '探测完成 · 边缘接入链路正常';
    } catch (e) {
      status.textContent = '探测中断：' + (e && e.message ? e.message : '网络异常');
    } finally {
      btn.disabled = false;
    }
  }
</script>
</body>
</html>
HTML_EOF
chmod 644 "${WEB_ROOT}/index.html"

# ==============================================================================
# 7. 备份原有配置、生成 Nginx 站点配置并支持原子回滚
# ==============================================================================
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
declare -A BACKUP_MAP=()
declare -a NEW_CONFS=()
declare -a REMOVED_ENABLED=()
declare -a TEMP_FILES=()

cleanup_temps() {
    for f in "${TEMP_FILES[@]:-}"; do
        [[ -n "$f" ]] && rm -f "$f"
    done
}
trap cleanup_temps EXIT

rollback_all() {
    warn "检测到异常，正在全量恢复原 Nginx 配置..."
    for domain in "${!BACKUP_MAP[@]}"; do
        local bak="${BACKUP_MAP[$domain]}"
        local conf="${AVAILABLE_DIR}/${domain}"
        [[ -L "$conf" ]] && conf=$(readlink -f "$conf")
        cp -a "$bak" "$conf"
        ln -sfn "$conf" "${ENABLED_DIR}/${domain}"
    done
    for domain in "${NEW_CONFS[@]:-}"; do
        [[ -z "$domain" ]] && continue
        rm -f "${ENABLED_DIR}/${domain}" "${AVAILABLE_DIR}/${domain}"
    done
    for old_name in "${REMOVED_ENABLED[@]:-}"; do
        [[ -z "$old_name" ]] && continue
        if [[ -e "${AVAILABLE_DIR}/${old_name}" ]]; then
            ln -sfn "${AVAILABLE_DIR}/${old_name}" "${ENABLED_DIR}/${old_name}"
        fi
    done
    nginx -t >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true
}

# 自动停用不在本次输入域名列表中的先前旧站点（不顾及旧域名，防止旧域名干扰或占用 443）
shopt -s nullglob
for enabled_file in "${ENABLED_DIR}"/*; do
    old_name=$(basename "$enabled_file")
    if [[ -z "${SEEN_DOMAINS[$old_name]:-}" ]]; then
        rm -f "$enabled_file"
        [[ "$old_name" != "default" ]] && REMOVED_ENABLED+=("$old_name") && info "已从 sites-enabled 移除旧站点：${old_name}"
    fi
done
shopt -u nullglob

USE_MODERN_HTTP2=0
if nginx_supports_http2_directive; then
    USE_MODERN_HTTP2=1
fi

for domain in "${DOMAINS[@]}"; do
    conf_path="${AVAILABLE_DIR}/${domain}"
    enabled_path="${ENABLED_DIR}/${domain}"

    if [[ -e "$conf_path" ]]; then
        if [[ -L "$conf_path" ]]; then
            resolved=$(readlink -f "$conf_path" || true)
            [[ -z "$resolved" || ! -f "$resolved" ]] && error "站点配置符号链接无效：$conf_path"
            conf_path="$resolved"
        fi
        bak_path="${conf_path}.backup-${TIMESTAMP}"
        cp -a "$conf_path" "$bak_path"
        BACKUP_MAP[$domain]="$bak_path"
        info "[${domain}] 原配置已备份：${bak_path}"
    else
        NEW_CONFS+=("$domain")
    fi

    tmp_conf=$(mktemp "/tmp/nginx-${domain}.XXXXXX")
    TEMP_FILES+=("$tmp_conf")

    if [[ "$LISTEN_MODE" == "1" ]]; then
        if (( USE_MODERN_HTTP2 == 1 )); then
            HTTPS_LISTEN_BLOCK="    listen 127.0.0.1:${INTERNAL_HTTPS_PORT} ssl;
    http2 on;"
        else
            HTTPS_LISTEN_BLOCK="    listen 127.0.0.1:${INTERNAL_HTTPS_PORT} ssl http2;"
        fi
    else
        if (( USE_MODERN_HTTP2 == 1 )); then
            HTTPS_LISTEN_BLOCK="    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;"
        else
            HTTPS_LISTEN_BLOCK="    listen 443 ssl http2;
    listen [::]:443 ssl http2;"
        fi
    fi

    cat > "$tmp_conf" <<EOF
server {
    listen 80;
    listen [::]:80;

    server_name ${domain};

    root ${WEB_ROOT};
    index index.html;
    charset utf-8;

    location = /api/ping {
        default_type application/json;
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        return 200 '{"status":"ok","service":"edge-speedtest-node"}\n';
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}

server {
${HTTPS_LISTEN_BLOCK}

    server_name ${domain};

    ssl_certificate ${DOMAIN_CERT[$domain]};
    ssl_certificate_key ${DOMAIN_KEY[$domain]};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    root ${WEB_ROOT};
    index index.html;
    charset utf-8;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location = /api/ping {
        default_type application/json;
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        return 200 '{"status":"ok","service":"edge-speedtest-node"}\n';
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

    if [[ -f "$conf_path" ]]; then
        chmod --reference="$conf_path" "$tmp_conf" 2>/dev/null || chmod 644 "$tmp_conf"
        chown --reference="$conf_path" "$tmp_conf" 2>/dev/null || true
    else
        chmod 644 "$tmp_conf"
    fi
    mv -f "$tmp_conf" "$conf_path"
    ln -sfn "$conf_path" "$enabled_path"
done

rm -f /etc/nginx/sites-enabled/default

# ==============================================================================
# 8. 检测 Nginx 配置、重启服务并逐个域名校验 HTTPS 200
# ==============================================================================
info "检测 Nginx 配置..."
if ! nginx -t; then
    rollback_all
    error "新配置检测失败，已恢复原配置"
fi

info "重启 Nginx 服务..."
if ! systemctl restart nginx; then
    rollback_all
    error "Nginx 重启失败（请用 ss -lntp | grep 443 检查是否有其他配置仍占用冲突端口），已恢复原配置"
fi

if ! ss -lnt | grep -qE ":${VERIFY_PORT}[[:space:]]"; then
    rollback_all
    error "Nginx 未监听 ${VERIFY_PORT} 端口，已恢复原配置"
fi

for domain in "${DOMAINS[@]}"; do
    PAGE_RESP=$(curl -ksS \
        --resolve "${domain}:${VERIFY_PORT}:127.0.0.1" \
        -w $'\n%{http_code}' \
        "https://${domain}:${VERIFY_PORT}/" || true)

    PAGE_STATUS=$(printf '%s\n' "$PAGE_RESP" | tail -n 1)
    PAGE_BODY=$(printf '%s\n' "$PAGE_RESP" | sed '$d')

    if [[ "$PAGE_STATUS" != "200" ]]; then
        rollback_all
        error "[${domain}] 本机 HTTPS 首页验证状态码为 ${PAGE_STATUS}（预期 200），已恢复原配置"
    fi

    if ! grep -q "边缘节点网络质量监测台" <<< "$PAGE_BODY"; then
        rollback_all
        error "[${domain}] 本机 HTTPS 首页响应内容不符合测速页预期，已恢复原配置"
    fi

    info "[${domain}] 本机 HTTPS 200 测速伪装页校验通过！"
done

echo
echo "============================================================"
echo -e "${GREEN}全部域名部署完成！${NC}"
echo
echo " 已生效域名 (${#DOMAINS[@]} 个)："
for domain in "${DOMAINS[@]}"; do
    echo "   - ${domain}  (证书: ${DOMAIN_CERT[$domain]})"
done
echo
echo " HTTPS 监听地址： ${LISTEN_SUMMARY}"
echo " HTTP 状态码：    200 OK（边缘节点网络质量监测台）"
echo " SSL 续期引擎：   acme.sh (/root/.acme.sh，续期自动 reload nginx)"
if [[ "$LISTEN_MODE" == "1" ]]; then
    echo " 公网 443 状态：  已腾出给 relay-node 多 SNI 分流"
    echo " 面板回落地址：   RelayPanel 设备组「SNI 兜底回落地址」保持默认 127.0.0.1:${INTERNAL_HTTPS_PORT}"
fi
echo "============================================================"
echo

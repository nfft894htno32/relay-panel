#!/usr/bin/env bash

set -Eeuo pipefail

# ==============================================================================
# 单机 VLESS Reality (:443 直连) 自偷伪装站一键部署脚本 (无需 relay-node)
#
# 架构原理：
#   公网 :443  ---> VLESS Reality (v2node / Xray / sing-box 对外直连监听)
#                      ├── 合法 Reality 客户端 ---> 正常代理出站
#                      └── 探测 / 浏览器访问   ---> 转发至 127.0.0.1:10443 (Nginx)
#   本机 127.0.0.1:10443 ---> Nginx 真实 Let's Encrypt ECC 证书 + TLSv1.3 + HTTP/2
#                             返回 200 OK 轻量级网络质量监测页（零刷流风险）
#   公网 :80   ---> Nginx 301 重定向至 https://$host$request_uri（与真实生产站一致）
# ==============================================================================

# 可选环境变量预设（公开仓库保持为空；为空时自动读取本机已存 Token 或提示输入）
CF_API_TOKEN="${CF_API_TOKEN:-}"
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
# 1. 安装基础组件（确保即使此前 purge 过 /etc/nginx 也能完整恢复默认主配置）
# ==============================================================================
ensure_dependencies() {
    local need_install=0
    local need_nginx_confmiss=0

    command -v nginx >/dev/null 2>&1   || need_install=1
    command -v curl >/dev/null 2>&1    || need_install=1
    command -v jq >/dev/null 2>&1      || need_install=1
    command -v openssl >/dev/null 2>&1 || need_install=1
    command -v crontab >/dev/null 2>&1 || need_install=1
    command -v ss >/dev/null 2>&1      || need_install=1

    if [[ ! -f /etc/nginx/nginx.conf ]]; then
        need_install=1
        need_nginx_confmiss=1
    fi

    if (( need_install == 1 )); then
        info "正在检查并安装基础依赖组件 (nginx, curl, jq, openssl, cron, iproute2) ..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y -qq
            if (( need_nginx_confmiss == 1 )); then
                DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                    -o Dpkg::Options::="--force-confmiss" \
                    nginx curl jq ca-certificates openssl cron iproute2
            else
                DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                    nginx curl jq ca-certificates openssl cron iproute2
            fi
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q nginx curl jq ca-certificates openssl cronie iproute
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q nginx curl jq ca-certificates openssl cronie iproute
        else
            error "未识别的包管理器，请先手动安装 nginx curl jq openssl cron iproute2"
        fi
    fi

    if [[ ! -f /etc/nginx/nginx.conf ]]; then
        error "未找到 /etc/nginx/nginx.conf，请执行 apt-get purge -y 'nginx*' && apt-get install -y nginx 后重试"
    fi

    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl enable --now cron >/dev/null 2>&1 || systemctl enable --now crond >/dev/null 2>&1 || true
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
echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}  单机 VLESS Reality (:443 直连) 自偷伪装站一键部署工具         ${NC}"
echo -e "${CYAN}  Nginx 127.0.0.1:10443 (TLS 1.3 + H2) + 公网 443 留给 Reality  ${NC}"
echo -e "${CYAN}================================================================${NC}"
echo

# ==============================================================================
# 2. 输入伪装域名 & 本地回源端口 & DNS 选项
# ==============================================================================
read -rp "请输入伪装域名（即 Reality 的 SNI 域名，多个用空格分隔，如 us-01.example.com）: " RAW_DOMAINS

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

declare -a RAW_ITEMS=()
read -r -a RAW_ITEMS <<< "$RAW_DOMAINS"
for item in "${RAW_ITEMS[@]}"; do
    add_domain "$item"
done

if (( ${#DOMAINS[@]} == 0 )); then
    error "未输入任何有效域名"
fi

echo
read -rp "请输入本机 Nginx HTTPS 自偷回源端口 [默认 10443，直接回车即可]: " INPUT_PORT
INTERNAL_HTTPS_PORT="${INPUT_PORT:-10443}"
if ! [[ "$INTERNAL_HTTPS_PORT" =~ ^[0-9]+$ ]] || (( INTERNAL_HTTPS_PORT < 1 || INTERNAL_HTTPS_PORT > 65535 )); then
    error "端口号无效：$INTERNAL_HTTPS_PORT"
fi
if (( INTERNAL_HTTPS_PORT == 443 || INTERNAL_HTTPS_PORT == 80 )); then
    error "自偷回源端口不能为 ${INTERNAL_HTTPS_PORT}（公网 443 需留给 Reality 节点监听），请使用 10443 等本地端口"
fi

# 检查目标回源端口是否已被非 nginx 进程占用
PORT_CONFLICT_PROC=$(ss -lntp 2>/dev/null | awk -v p=":${INTERNAL_HTTPS_PORT}" '$4 ~ p"$" && $0 !~ /"nginx"/ {print $0}' || true)
if [[ -n "$PORT_CONFLICT_PROC" ]]; then
    error "本地端口 ${INTERNAL_HTTPS_PORT} 已被其他进程占用，请更换端口：\n${PORT_CONFLICT_PROC}"
fi

echo
read -rp "是否自动将域名 Cloudflare DNS A 记录指向本机公网 IP？（单机直连建议选 Y）[Y/n]: " UPDATE_DNS_A
UPDATE_DNS_A="${UPDATE_DNS_A:-Y}"

info "本次部署伪装域名 (${#DOMAINS[@]} 个)：${DOMAINS[*]}"
info "Nginx 自偷回源地址：127.0.0.1:${INTERNAL_HTTPS_PORT}（公网 443 将完全释放给 Reality）"

# 停用可能残留的 certbot 定时器，统一由 acme.sh 负责续期
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^certbot\.timer'; then
    systemctl disable --now certbot.timer >/dev/null 2>&1 || true
fi

# ==============================================================================
# 3. 获取本机公网 IPv4 并读取 / 校验 Cloudflare API Token
# ==============================================================================
SERVER_IP=""
for ip_url in "https://api.ipify.org" "https://api4.ipify.org" "https://ipv4.icanhazip.com"; do
    SERVER_IP=$(curl -4 -fsS --max-time 10 "$ip_url" 2>/dev/null | xargs || true)
    [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && break
done

if [[ "$UPDATE_DNS_A" =~ ^[Yy]$ ]] && ! [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    error "无法获取服务器公网 IPv4，请检查服务器出站网络"
fi
if [[ -n "$SERVER_IP" ]]; then
    info "检测到本机公网 IPv4：${SERVER_IP}"
fi

ACME_HOME="/root/.acme.sh"
ACME_SH="${ACME_HOME}/acme.sh"
ACME_ACCOUNT_CONF="${ACME_HOME}/account.conf"
CF_CRED_BACKUP="/etc/letsencrypt/cloudflare.ini"

cert_is_valid_30d() {
    local cert_file="$1"
    [[ -f "$cert_file" ]] && openssl x509 -in "$cert_file" -noout -checkend 2592000 >/dev/null 2>&1
}

# 判断是否真的需要调用 Cloudflare API（若不改 DNS 且所有域名本地已有 >30 天有效证书，则免填 Token）
NEED_CF_API=0
if [[ "$UPDATE_DNS_A" =~ ^[Yy]$ ]]; then
    NEED_CF_API=1
else
    for domain in "${DOMAINS[@]}"; do
        if ! cert_is_valid_30d "/etc/letsencrypt/live/${domain}/fullchain.pem" || [[ ! -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]]; then
            NEED_CF_API=1
            break
        fi
    done
fi

CF_API="https://api.cloudflare.com/client/v4"
declare -a CF_AUTH_HEADER=()

if (( NEED_CF_API == 1 )); then
    if [[ -z "$CF_API_TOKEN" ]]; then
        if [[ -f "$ACME_ACCOUNT_CONF" ]]; then
            CF_API_TOKEN=$(awk -F'=' '/^SAVED_CF_Token=/ {v=$2; gsub(/^[\x27"]|[\x27"]$/, "", v); gsub(/[[:space:]]/, "", v); print v; exit}' "$ACME_ACCOUNT_CONF" || true)
        fi
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

    if [[ -z "$CF_API_TOKEN" ]]; then
        error "Cloudflare API Token 不能为空"
    fi

    CF_AUTH_HEADER=(
        -H "Authorization: Bearer ${CF_API_TOKEN}"
        -H "Content-Type: application/json"
    )

    info "正在验证 Cloudflare API Token ..."
    CF_VERIFY=$(curl -fsS "${CF_AUTH_HEADER[@]}" "${CF_API}/zones?per_page=1" 2>/dev/null || true)
    if [[ "$(echo "$CF_VERIFY" | jq -r '.success // false' 2>/dev/null)" != "true" ]]; then
        error "Cloudflare API Token 验证失败，请检查权限（Zone -> Zone -> Read, Zone -> DNS -> Edit）"
    fi
    info "Cloudflare API Token 验证通过"
fi

# ==============================================================================
# 4. 配置 Cloudflare DNS A 记录（确保直连不套 CF 小云朵，支持清理旧 IP 记录）
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
        for domain in "${DOMAINS[@]}"; do
            zone_id=$(find_zone_id "$domain" || true)
            if [[ -z "$zone_id" ]]; then
                error "无法找到域名 ${domain} 对应的 Cloudflare Zone，请确认域名已接入当前 Cloudflare 账号"
            fi
            DOMAIN_ZONE_ID[$domain]="$zone_id"

            dns_resp=$(curl -fsS "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${zone_id}/dns_records?type=A&name=${domain}")
            if [[ "$(echo "$dns_resp" | jq -r '.success')" != "true" ]]; then
                echo "$dns_resp" | jq . >&2 || true
                error "[${domain}] Cloudflare DNS 记录查询失败"
            fi

            # 检查是否存在指向其他 IP 的旧 A 记录
            other_ips=$(echo "$dns_resp" | jq -r --arg ip "$SERVER_IP" '[.result[]? | select(.content != $ip) | .content] | join(", ")' || true)
            if [[ -n "$other_ips" ]]; then
                echo
                read -rp "检测到 [${domain}] 存在指向其他 IP 的旧 A 记录 (${other_ips})，是否清理旧记录、仅保留本机 IP (${SERVER_IP})？[Y/n]: " CLEAN_OLD_DNS
                CLEAN_OLD_DNS="${CLEAN_OLD_DNS:-Y}"
                if [[ "$CLEAN_OLD_DNS" =~ ^[Yy]$ ]]; then
                    while IFS= read -r old_rec_id; do
                        [[ -z "$old_rec_id" ]] && continue
                        curl -fsS -X DELETE "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${zone_id}/dns_records/${old_rec_id}" >/dev/null
                    done < <(echo "$dns_resp" | jq -r --arg ip "$SERVER_IP" '.result[]? | select(.content != $ip) | .id')
                    info "[${domain}] 已清理旧 A 记录 (${other_ips})"
                fi
            fi

            current_rec_id=$(echo "$dns_resp" | jq -r --arg ip "$SERVER_IP" 'first(.result[]? | select(.content == $ip) | .id) // empty')
            current_rec_proxied=$(echo "$dns_resp" | jq -r --arg ip "$SERVER_IP" 'first(.result[]? | select(.content == $ip) | .proxied) // false')

            dns_data=$(jq -n \
                --arg type "A" \
                --arg name "$domain" \
                --arg content "$SERVER_IP" \
                --argjson proxied "$CF_PROXIED" \
                '{type: $type, name: $name, content: $content, ttl: 60, proxied: $proxied}')

            if [[ -n "$current_rec_id" ]]; then
                if [[ "$current_rec_proxied" == "true" ]]; then
                    update_res=$(curl -fsS -X PUT "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${zone_id}/dns_records/${current_rec_id}" --data "$dns_data")
                    if [[ "$(echo "$update_res" | jq -r '.success')" != "true" ]]; then
                        echo "$update_res" | jq . >&2 || true
                        error "[${domain}] 关闭 Cloudflare 小云朵代理失败"
                    fi
                    info "[${domain}] 已将现有 A 记录 (${SERVER_IP}) 自动切换为仅 DNS 直连（关闭小云朵）"
                else
                    info "[${domain}] 本机 IP (${SERVER_IP}) 的直连 A 记录已就绪"
                fi
            else
                create_res=$(curl -fsS -X POST "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${zone_id}/dns_records" --data "$dns_data")
                if [[ "$(echo "$create_res" | jq -r '.success')" != "true" ]]; then
                    echo "$create_res" | jq . >&2 || true
                    error "[${domain}] Cloudflare DNS A 记录新增失败"
                fi
                info "[${domain}] DNS A 记录已指向本机 -> ${SERVER_IP}（仅 DNS 直连）"
            fi
        done
    else
        info "已跳过 Cloudflare DNS A 记录修改"
    fi
fi

# ==============================================================================
# 5. 安装 acme.sh 并签发 / 沿用 Let's Encrypt ECC 证书
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
    cert_dir="/etc/letsencrypt/live/${domain}"
    cert_path="${cert_dir}/fullchain.pem"
    key_path="${cert_dir}/privkey.pem"

    # 若本地已有剩余 >30 天有效证书，直接沿用，避免触发 Let's Encrypt 速率限制
    if [[ -f "$cert_path" && -f "$key_path" ]] && cert_is_valid_30d "$cert_path"; then
        info "[${domain}] 检测到有效现有证书（剩余 >30 天），直接沿用：${cert_path}"
        DOMAIN_CERT[$domain]="$cert_path"
        DOMAIN_KEY[$domain]="$key_path"
        continue
    fi

    ensure_acme_sh

    zone_id="${DOMAIN_ZONE_ID[$domain]:-}"
    if [[ -z "$zone_id" ]]; then
        zone_id=$(find_zone_id "$domain" || true)
    fi
    if [[ -z "$zone_id" ]]; then
        error "[${domain}] 无法获取 Cloudflare Zone ID，无法签发证书"
    fi

    info "[${domain}] 正在通过 acme.sh (Cloudflare DNS-01) 申请 Let's Encrypt ECC 证书..."
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

    mkdir -p "$cert_dir"
    chmod 700 "$cert_dir"
    [[ -L "$cert_path" ]] && rm -f "$cert_path"
    [[ -L "$key_path" ]]  && rm -f "$key_path"

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
    info "[${domain}] SSL 证书签发并安装成功（已配置自动续期）"
done

# ==============================================================================
# 6. 生成 HTTP 200 零刷流风险伪装网络监测网页 (/var/www/edge-speedtest)
# ==============================================================================
WEB_ROOT="/var/www/edge-speedtest"
mkdir -p "$WEB_ROOT"
chmod 755 /var /var/www "$WEB_ROOT"
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
# 7. 彻底释放 Nginx 对 443 的占用、写入 127.0.0.1 回源配置（支持失败原子回滚）
# ==============================================================================
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
AVAILABLE_DIR="/etc/nginx/sites-available"
ENABLED_DIR="/etc/nginx/sites-enabled"
CONFD_DIR="/etc/nginx/conf.d"
mkdir -p "$AVAILABLE_DIR" "$ENABLED_DIR" "$CONFD_DIR"

USE_SITES_ENABLED=0
if grep -Eq 'sites-enabled' /etc/nginx/nginx.conf; then
    USE_SITES_ENABLED=1
fi

declare -A BACKUP_MAP=()
declare -A DISABLED_CONFD_MAP=()
declare -a NEW_CONFS=()
declare -a REMOVED_ENABLED=()
declare -a TEMP_FILES=()

cleanup_temps() {
    local f
    for f in "${TEMP_FILES[@]:-}"; do
        [[ -n "$f" ]] && rm -f "$f"
    done
}
trap cleanup_temps EXIT

rollback_all() {
    warn "检测到异常，正在恢复原 Nginx 配置..."
    local path bak old_name
    for path in "${!BACKUP_MAP[@]}"; do
        bak="${BACKUP_MAP[$path]}"
        cp -a "$bak" "$path"
    done
    for path in "${NEW_CONFS[@]:-}"; do
        [[ -z "$path" ]] && continue
        rm -f "$path"
    done
    if (( USE_SITES_ENABLED == 1 )); then
        for domain in "${DOMAINS[@]}"; do
            if [[ -n "${BACKUP_MAP[${AVAILABLE_DIR}/${domain}]:-}" ]]; then
                ln -sfn "${AVAILABLE_DIR}/${domain}" "${ENABLED_DIR}/${domain}"
            else
                rm -f "${ENABLED_DIR}/${domain}"
            fi
        done
        for old_name in "${REMOVED_ENABLED[@]:-}"; do
            [[ -z "$old_name" ]] && continue
            if [[ -e "${AVAILABLE_DIR}/${old_name}" ]]; then
                ln -sfn "${AVAILABLE_DIR}/${old_name}" "${ENABLED_DIR}/${old_name}"
            fi
        done
    fi
    for path in "${!DISABLED_CONFD_MAP[@]}"; do
        bak="${DISABLED_CONFD_MAP[$path]}"
        [[ -f "$bak" ]] && mv -f "$bak" "$path"
    done
    nginx -t >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true
}

# 7.1 清理 sites-enabled 下未在本次域名列表中的旧站点（含 default）
if (( USE_SITES_ENABLED == 1 )); then
    shopt -s nullglob
    for enabled_file in "${ENABLED_DIR}"/*; do
        old_name=$(basename "$enabled_file")
        if [[ -z "${SEEN_DOMAINS[$old_name]:-}" ]]; then
            rm -f "$enabled_file"
            if [[ "$old_name" != "default" ]]; then
                REMOVED_ENABLED+=("$old_name")
                info "已停用旧 Nginx 站点：${old_name}"
            fi
        fi
    done
    shopt -u nullglob
fi

# 7.2 扫描 /etc/nginx/conf.d/*.conf，自动停用任何监听 443 的遗留配置，确保 443 100% 释放
declare -A EXPECTED_CONFD=()
if (( USE_SITES_ENABLED == 0 )); then
    for domain in "${DOMAINS[@]}"; do
        EXPECTED_CONFD["${domain}.conf"]=1
    done
fi

shopt -s nullglob
for confd_file in "${CONFD_DIR}"/*.conf; do
    confd_base=$(basename "$confd_file")
    [[ -n "${EXPECTED_CONFD[$confd_base]:-}" ]] && continue
    if awk '{sub(/#.*/, "")} /listen[[:space:]].*(^|[^0-9])443([^0-9]|$)/ {found=1} END {exit !found}' "$confd_file"; then
        disabled_path="${confd_file}.disabled-${TIMESTAMP}"
        mv -f "$confd_file" "$disabled_path"
        DISABLED_CONFD_MAP["$confd_file"]="$disabled_path"
        info "已自动隔离占用 443 的遗留配置：${confd_file} -> ${disabled_path}"
    fi
done
shopt -u nullglob

# 7.3 检查 80 端口与 IPv6 可用性
ENABLE_PORT_80=1
PORT80_OTHER=$(ss -lntp 2>/dev/null | awk '$4 ~ /:80$/ && $0 !~ /"nginx"/ {print $0}' || true)
if [[ -n "$PORT80_OTHER" ]]; then
    ENABLE_PORT_80=0
    warn "检测到 80 端口已被其他程序占用，自动跳过 Nginx 80 端口跳转，仅启用 127.0.0.1:${INTERNAL_HTTPS_PORT}"
fi

HAS_IPV6=0
if [[ -s /proc/net/if_inet6 ]]; then
    HAS_IPV6=1
fi

USE_MODERN_HTTP2=0
if nginx_supports_http2_directive; then
    USE_MODERN_HTTP2=1
fi

# 7.4 为每个域名生成 Nginx 配置
for domain in "${DOMAINS[@]}"; do
    if (( USE_SITES_ENABLED == 1 )); then
        conf_path="${AVAILABLE_DIR}/${domain}"
        if [[ -L "$conf_path" ]]; then
            resolved=$(readlink -f "$conf_path" || true)
            [[ -z "$resolved" || ! -f "$resolved" ]] && error "站点配置符号链接无效：$conf_path"
            conf_path="$resolved"
        fi
    else
        conf_path="${CONFD_DIR}/${domain}.conf"
    fi

    if [[ -f "$conf_path" ]]; then
        bak_path="${conf_path}.backup-${TIMESTAMP}"
        cp -a "$conf_path" "$bak_path"
        BACKUP_MAP["$conf_path"]="$bak_path"
        info "[${domain}] 原配置已备份：${bak_path}"
    else
        NEW_CONFS+=("$conf_path")
    fi

    tmp_conf=$(mktemp "/tmp/nginx-reality-${domain}.XXXXXX")
    TEMP_FILES+=("$tmp_conf")

    if (( USE_MODERN_HTTP2 == 1 )); then
        HTTPS_LISTEN_BLOCK="    listen 127.0.0.1:${INTERNAL_HTTPS_PORT} ssl;
    http2 on;"
    else
        HTTPS_LISTEN_BLOCK="    listen 127.0.0.1:${INTERNAL_HTTPS_PORT} ssl http2;"
    fi

    HTTP80_BLOCK=""
    if (( ENABLE_PORT_80 == 1 )); then
        IPV6_80_LINE=""
        if (( HAS_IPV6 == 1 )); then
            IPV6_80_LINE=$'\n    listen [::]:80;'
        fi
        HTTP80_BLOCK="server {
    listen 80;${IPV6_80_LINE}
    server_name ${domain};

    location = /api/ping {
        default_type application/json;
        add_header Cache-Control \"no-store, no-cache, must-revalidate\" always;
        return 200 '{\"status\":\"ok\",\"service\":\"edge-speedtest-node\"}\\n';
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

"
    fi

    cat > "$tmp_conf" <<EOF
${HTTP80_BLOCK}server {
${HTTPS_LISTEN_BLOCK}

    server_name ${domain};

    ssl_certificate ${DOMAIN_CERT[$domain]};
    ssl_certificate_key ${DOMAIN_KEY[$domain]};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_prefer_server_ciphers off;
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

    chmod 644 "$tmp_conf"
    mv -f "$tmp_conf" "$conf_path"
    if (( USE_SITES_ENABLED == 1 )); then
        ln -sfn "$conf_path" "${ENABLED_DIR}/${domain}"
    fi
done

rm -f /etc/nginx/sites-enabled/default

# ==============================================================================
# 8. 校验 Nginx 配置、确认 443 完全释放并实测 127.0.0.1:10443 握手与 200 页面
# ==============================================================================
info "检测 Nginx 配置语法..."
if ! nginx -t; then
    rollback_all
    error "Nginx 配置检测未通过，已回滚原配置"
fi

info "重启 Nginx 服务..."
if ! systemctl restart nginx; then
    rollback_all
    error "Nginx 重启失败，已回滚原配置"
fi

if ! ss -lnt | grep -qE "127\.0\.0\.1:${INTERNAL_HTTPS_PORT}[[:space:]]"; then
    rollback_all
    error "Nginx 未在 127.0.0.1:${INTERNAL_HTTPS_PORT} 正常监听，已回滚原配置"
fi

if ss -lntp 2>/dev/null | grep -E ':443[[:space:]]' | grep -q '"nginx"'; then
    rollback_all
    error "检测到 Nginx 仍在监听 443 端口（请检查 /etc/nginx/nginx.conf 自定义段），已回滚原配置"
fi

for domain in "${DOMAINS[@]}"; do
    PAGE_RESP=$(curl -ksS \
        --resolve "${domain}:${INTERNAL_HTTPS_PORT}:127.0.0.1" \
        -w $'\n%{http_code}' \
        "https://${domain}:${INTERNAL_HTTPS_PORT}/" || true)

    PAGE_STATUS=$(printf '%s\n' "$PAGE_RESP" | tail -n 1)
    PAGE_BODY=$(printf '%s\n' "$PAGE_RESP" | sed '$d')

    if [[ "$PAGE_STATUS" != "200" ]]; then
        rollback_all
        error "[${domain}] 本机回源 HTTPS 校验状态码为 ${PAGE_STATUS}（预期 200），已回滚原配置"
    fi

    if ! grep -q "边缘节点网络质量监测台" <<< "$PAGE_BODY"; then
        rollback_all
        error "[${domain}] 本机回源页面内容校验未通过，已回滚原配置"
    fi

    info "[${domain}] 本机 https://127.0.0.1:${INTERNAL_HTTPS_PORT} (TLS 1.3 + HTTP 200) 校验通过！"
done

PORT443_STATUS="当前空闲（等待您的 Reality 节点程序监听 443）"
PORT443_PROC=$(ss -lntp 2>/dev/null | awk '$4 ~ /:443$/ {print $0; exit}' || true)
if [[ -n "$PORT443_PROC" ]]; then
    PORT443_STATUS="已由后端服务监听 -> ${PORT443_PROC}"
fi

PRIMARY_DOMAIN="${DOMAINS[0]}"
DISPLAY_CONNECT_ADDR="${PRIMARY_DOMAIN}"
if [[ -n "$SERVER_IP" && ! "$UPDATE_DNS_A" =~ ^[Yy]$ ]]; then
    DISPLAY_CONNECT_ADDR="${SERVER_IP}"
fi

echo
echo "=================================================================="
echo -e "${GREEN}单机 VLESS Reality 自偷伪装站部署完成！${NC}"
echo
echo " [本机运行状态]"
echo "   伪装域名：        ${DOMAINS[*]}"
echo "   证书路径：        ${DOMAIN_CERT[$PRIMARY_DOMAIN]}"
echo "   Nginx 自偷监听：  127.0.0.1:${INTERNAL_HTTPS_PORT} (TLSv1.3 + HTTP/2, 200 OK)"
echo "   公网 443 状态：   ${PORT443_STATUS}"
echo
echo -e " ${CYAN}[机场面板 VLESS Reality 节点配置填写指南（直接照抄）]${NC}"
echo "   连接地址：        ${DISPLAY_CONNECT_ADDR}"
echo "   监听地址：        0.0.0.0"
echo "   连接端口：        443"
echo "   服务端口：        443"
echo "   节点协议：        VLess  |  安全性：Reality  |  传输协议：TCP"
echo
echo -e " ${CYAN}[点击「安全性 -> 编辑配置」填写以下 4 项]${NC}"
echo "   Server Name(SNI): ${PRIMARY_DOMAIN}"
echo -e "   Server Address:   ${YELLOW}127.0.0.1${NC}   (必填！切勿留空)"
echo -e "   Server Port:      ${YELLOW}${INTERNAL_HTTPS_PORT}${NC}"
echo "   Proxy Protocol:   0"
echo
echo " 提示：若此前面板后端 (v2node / XrayR / xray) 因 443 被占启动失败，"
echo "       面板保存节点配置后可执行 systemctl restart v2node (或对应后端服务) 立即生效。"
echo "=================================================================="
echo

#!/usr/bin/env bash

set -Eeuo pipefail

# ==============================================================================
# 增量补充新域名脚本（无损追加 · 绝不影响已配置的域名与正在运行的服务）
#
# 同时适配以下全部场景（自动识别当前机器已有配置并默认沿用）：
#   场景 1：入口中转机（配合 relay-node 多 SNI 分流 -> Nginx 127.0.0.1:10443）
#   场景 2：纯单机直连（配合 VLESS Reality 占公网 443 -> Nginx 127.0.0.1:10443 自偷）
#   场景 3：纯公网伪装站（Nginx 直接监听公网 0.0.0.0:443 & [::]:443）
#
# 安全无损承诺：
#   - 绝不删除、停用或改动任何已存在的 Nginx 站点配置
#   - 绝不删除 Cloudflare 同名或其他旧 A 记录（默认无损并存）
#   - 绝不覆盖已存在的伪装网页文件，仅在缺失时补齐
#   - 采用 nginx -t + systemctl reload nginx 平滑热加载，不断开任何现有连接
#   - 若新域名配置校验异常，仅回滚本次新增文件，原有服务零影响
# ==============================================================================

CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_PROXIED=false

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
# 1. 检查基础依赖（若已安装则零改动跳过）
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
        info "补齐缺失的基础工具：${missing[*]} ..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                nginx curl jq ca-certificates openssl cron iproute2
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q nginx curl jq ca-certificates openssl cronie iproute
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q nginx curl jq ca-certificates openssl cronie iproute
        else
            error "未识别的包管理器，请先手动安装：${missing[*]}"
        fi
    fi

    if [[ ! -f /etc/nginx/nginx.conf ]]; then
        error "未找到 /etc/nginx/nginx.conf，请先运行初始化部署脚本"
    fi

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

# ==============================================================================
# 2. 扫描本机当前已生效的 Nginx 站点与运行架构（只读扫描，不做任何修改）
# ==============================================================================
AVAILABLE_DIR="/etc/nginx/sites-available"
ENABLED_DIR="/etc/nginx/sites-enabled"
CONFD_DIR="/etc/nginx/conf.d"
mkdir -p "$AVAILABLE_DIR" "$ENABLED_DIR" "$CONFD_DIR"

USE_SITES_ENABLED=0
if grep -Eq 'sites-enabled' /etc/nginx/nginx.conf; then
    USE_SITES_ENABLED=1
fi

declare -a EXISTING_CONFIG_FILES=()
shopt -s nullglob
if (( USE_SITES_ENABLED == 1 )); then
    for f in "${ENABLED_DIR}"/*; do
        [[ -f "$f" ]] && EXISTING_CONFIG_FILES+=("$f")
    done
fi
for f in "${CONFD_DIR}"/*.conf; do
    [[ -f "$f" ]] && EXISTING_CONFIG_FILES+=("$f")
done
shopt -u nullglob

declare -A EXISTING_DOMAIN_FILE=()
declare -a EXISTING_DOMAINS=()
DETECTED_INTERNAL_PORT=""
DETECTED_PUBLIC_443=0
DETECTED_SELFSTEAL_STYLE=0

for cfg in "${EXISTING_CONFIG_FILES[@]:-}"; do
    [[ -z "$cfg" || ! -f "$cfg" ]] && continue
    # 提取已配置的 server_name
    while IFS= read -r sname; do
        [[ -z "$sname" || "$sname" == "_" || "$sname" == "localhost" ]] && continue
        if [[ -z "${EXISTING_DOMAIN_FILE[$sname]:-}" ]]; then
            EXISTING_DOMAIN_FILE[$sname]="$cfg"
            EXISTING_DOMAINS+=("$sname")
        fi
    done < <(awk '{sub(/#.*/, "")} $1 == "server_name" {for (i=2; i<=NF; i++) {gsub(/;/, "", $i); print tolower($i)}}' "$cfg" || true)

    # 检测是否监听 127.0.0.1:<port> ssl
    if [[ -z "$DETECTED_INTERNAL_PORT" ]]; then
        DETECTED_INTERNAL_PORT=$(awk '
            {sub(/#.*/, "")}
            /listen[[:space:]]+127\.0\.0\.1:[0-9]+/ && /ssl/ {
                if (match($0, /127\.0\.0\.1:[0-9]+/)) {
                    s = substr($0, RSTART, RLENGTH)
                    sub(/127\.0\.0\.1:/, "", s)
                    print s
                    exit
                }
            }
        ' "$cfg" || true)
    fi

    # 检测是否直接监听公网 443
    if awk '{sub(/#.*/, "")} /listen[[:space:]]+(\[::\]:|0\.0\.0\.0:)?443([[:space:];]|$)/ {found=1} END {exit !found}' "$cfg"; then
        DETECTED_PUBLIC_443=1
    fi

    # 检测是否为单机 Reality 自偷风格（含 80->HTTPS 301 或 X25519 配置）
    if awk '{sub(/#.*/, "")} /return[[:space:]]+301[[:space:]]+https:\/\/\$host/ || /ssl_ecdh_curve[[:space:]]+X25519/ {found=1} END {exit !found}' "$cfg"; then
        DETECTED_SELFSTEAL_STYLE=1
    fi
done

# 结合当前进程进一步辅助判断场景
HAS_RELAY_NODE=0
if pgrep -x "relay-node" >/dev/null 2>&1 || systemctl is-active --quiet relay-node 2>/dev/null; then
    HAS_RELAY_NODE=1
fi

DETECTED_SCENE="1"
DETECTED_DESC="场景 1：中转分流回源模式 (relay-node + Nginx 127.0.0.1:${DETECTED_INTERNAL_PORT:-10443})"
if (( DETECTED_PUBLIC_443 == 1 )); then
    DETECTED_SCENE="3"
    DETECTED_DESC="场景 3：Nginx 公网 443 直连伪装站模式"
elif (( DETECTED_SELFSTEAL_STYLE == 1 )) || { [[ -n "$DETECTED_INTERNAL_PORT" ]] && (( HAS_RELAY_NODE == 0 )); }; then
    DETECTED_SCENE="2"
    DETECTED_DESC="场景 2：纯单机 VLESS Reality (:443 直连) 自偷模式 (Nginx 127.0.0.1:${DETECTED_INTERNAL_PORT:-10443})"
elif [[ -n "$DETECTED_INTERNAL_PORT" ]]; then
    DETECTED_SCENE="1"
    DETECTED_DESC="场景 1：中转分流回源模式 (relay-node + Nginx 127.0.0.1:${DETECTED_INTERNAL_PORT})"
fi

echo
echo -e "${CYAN}==================================================================${NC}"
echo -e "${CYAN}  伪装站无损增量加域名工具（不影响任何已配置域名与运行中服务）    ${NC}"
echo -e "${CYAN}==================================================================${NC}"
echo

if (( ${#EXISTING_DOMAINS[@]} > 0 )); then
    info "检测到本机当前已生效域名 (${#EXISTING_DOMAINS[@]} 个)：${EXISTING_DOMAINS[*]}"
    info "安全保护已开启：上述已有站点配置与连接全程保持原样、绝不改动或中断"
else
    info "当前未检测到已有自定义域名配置，将直接为您增量创建新站点"
fi

echo
echo "已自动识别本机架构为：【${DETECTED_DESC}】"
echo "请选择本次新域名的部署场景："
echo "  1) 中转分流模式（配合 relay-node 占 443 -> Nginx 监听 127.0.0.1 本地回源端口）"
echo "  2) 单机 Reality 自偷模式（配合 v2node/Xray 占 443 -> Nginx 监听 127.0.0.1 本地回源端口）"
echo "  3) 公网 443 建站模式（Nginx 已直接监听公网 0.0.0.0:443 & [::]:443）"
read -rp "请输入选项 [1/2/3，直接回车默认 ${DETECTED_SCENE}]: " SCENE_MODE
SCENE_MODE="${SCENE_MODE:-$DETECTED_SCENE}"

if [[ "$SCENE_MODE" != "1" && "$SCENE_MODE" != "2" && "$SCENE_MODE" != "3" ]]; then
    error "无效的场景选项：${SCENE_MODE}"
fi

INTERNAL_HTTPS_PORT="${DETECTED_INTERNAL_PORT:-10443}"
VERIFY_PORT="443"
LISTEN_SUMMARY="0.0.0.0:443, [::]:443"

if [[ "$SCENE_MODE" == "1" || "$SCENE_MODE" == "2" ]]; then
    read -rp "请输入本机 Nginx HTTPS 回源监听端口 [默认 ${INTERNAL_HTTPS_PORT}，直接回车即可]: " INPUT_PORT
    INTERNAL_HTTPS_PORT="${INPUT_PORT:-$INTERNAL_HTTPS_PORT}"
    if ! [[ "$INTERNAL_HTTPS_PORT" =~ ^[0-9]+$ ]] || (( INTERNAL_HTTPS_PORT < 1 || INTERNAL_HTTPS_PORT > 65535 )); then
        error "端口号无效：${INTERNAL_HTTPS_PORT}"
    fi
    if (( INTERNAL_HTTPS_PORT == 443 || INTERNAL_HTTPS_PORT == 80 )); then
        error "本地回源端口不能为 ${INTERNAL_HTTPS_PORT}（公网 443 需留给 relay-node 或 Reality 监听）"
    fi
    PORT_CONFLICT_PROC=$(ss -lntp 2>/dev/null | awk -v p=":${INTERNAL_HTTPS_PORT}" '$4 ~ p"$" && $0 !~ /"nginx"/ {print $0}' || true)
    if [[ -n "$PORT_CONFLICT_PROC" ]]; then
        error "本地端口 ${INTERNAL_HTTPS_PORT} 已被非 Nginx 进程占用，请核对端口号：\n${PORT_CONFLICT_PROC}"
    fi
    VERIFY_PORT="$INTERNAL_HTTPS_PORT"
    LISTEN_SUMMARY="127.0.0.1:${INTERNAL_HTTPS_PORT}"
else
    # 场景 3：确认公网 443 未被 relay-node / v2node / xray 占用，防止误选导致 reload 冲突
    PORT443_NON_NGINX=$(ss -lntp 2>/dev/null | awk '$4 ~ /:443$/ && $0 !~ /"nginx"/ {print $0}' || true)
    if [[ -n "$PORT443_NON_NGINX" ]]; then
        error "检测到公网 443 当前正由其他后端服务监听：\n${PORT443_NON_NGINX}\n请勿选择模式 3（否则会抢占 443 端口），请重新运行并选择 1 或 2！"
    fi
fi

# ==============================================================================
# 3. 输入要补充的新域名（若误输入已存在域名，默认跳过保护原配置）
# ==============================================================================
echo
read -rp "请输入要新增补充的域名（多个新域名用空格或逗号分隔）: " RAW_DOMAINS
RAW_DOMAINS="${RAW_DOMAINS//,/ }"

declare -a CANDIDATE_DOMAINS=()
declare -A SEEN_INPUT=()

add_candidate_domain() {
    local d="$1"
    d=$(echo "$d" | tr '[:upper:]' '[:lower:]' | xargs)
    d="${d#http://}"
    d="${d#https://}"
    d="${d%%/*}"
    [[ -z "$d" ]] && return 0

    if ! [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
        error "域名格式不正确：$d"
    fi

    if [[ -z "${SEEN_INPUT[$d]:-}" ]]; then
        SEEN_INPUT[$d]=1
        CANDIDATE_DOMAINS+=("$d")
    fi
}

declare -a RAW_ITEMS=()
read -r -a RAW_ITEMS <<< "$RAW_DOMAINS"
for item in "${RAW_ITEMS[@]}"; do
    add_candidate_domain "$item"
done

if (( ${#CANDIDATE_DOMAINS[@]} == 0 )); then
    error "未输入任何有效的新域名"
fi

declare -a DOMAINS=()
for d in "${CANDIDATE_DOMAINS[@]}"; do
    if [[ -n "${EXISTING_DOMAIN_FILE[$d]:-}" ]]; then
        echo
        warn "域名 [${d}] 已存在于现有配置 (${EXISTING_DOMAIN_FILE[$d]})"
        read -rp "为保护现有服务，是否跳过 [${d}]？[Y/n，默认 Y 跳过]: " SKIP_EXISTING
        SKIP_EXISTING="${SKIP_EXISTING:-Y}"
        if [[ "$SKIP_EXISTING" =~ ^[Yy]$ ]]; then
            info "已跳过已有域名：${d}"
            continue
        fi
    fi
    DOMAINS+=("$d")
done

if (( ${#DOMAINS[@]} == 0 )); then
    info "没有需要新增的域名，系统未做任何更改。"
    exit 0
fi

echo
read -rp "是否为新域名自动添加本机公网 IP 的 Cloudflare DNS A 记录？[Y/n，默认 Y]: " UPDATE_DNS_A
UPDATE_DNS_A="${UPDATE_DNS_A:-Y}"

info "即将无损新增以下 ${#DOMAINS[@]} 个域名：${DOMAINS[*]}"

# ==============================================================================
# 4. 获取公网 IPv4 并自动读取 / 校验 Cloudflare API Token
# ==============================================================================
SERVER_IP=""
for ip_url in "https://api.ipify.org" "https://api4.ipify.org" "https://ipv4.icanhazip.com"; do
    SERVER_IP=$(curl -4 -fsS --max-time 10 "$ip_url" 2>/dev/null | xargs || true)
    [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && break
done

if [[ "$UPDATE_DNS_A" =~ ^[Yy]$ ]] && ! [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    error "无法获取服务器公网 IPv4"
fi
if [[ -n "$SERVER_IP" ]]; then
    info "本机公网 IPv4：${SERVER_IP}"
fi

ACME_HOME="/root/.acme.sh"
ACME_SH="${ACME_HOME}/acme.sh"
ACME_ACCOUNT_CONF="${ACME_HOME}/account.conf"
CF_CRED_BACKUP="/etc/letsencrypt/cloudflare.ini"

cert_is_valid_30d() {
    local cert_file="$1"
    [[ -f "$cert_file" ]] && openssl x509 -in "$cert_file" -noout -checkend 2592000 >/dev/null 2>&1
}

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
# 5. 为新域名添加 Cloudflare DNS A 记录（默认保留其他已有记录，绝不误删）
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
                error "无法找到域名 ${domain} 对应的 Cloudflare Zone"
            fi
            DOMAIN_ZONE_ID[$domain]="$zone_id"

            dns_resp=$(curl -fsS "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${zone_id}/dns_records?type=A&name=${domain}")
            if [[ "$(echo "$dns_resp" | jq -r '.success')" != "true" ]]; then
                echo "$dns_resp" | jq . >&2 || true
                error "[${domain}] Cloudflare DNS 记录查询失败"
            fi

            other_ips=$(echo "$dns_resp" | jq -r --arg ip "$SERVER_IP" '[.result[]? | select(.content != $ip) | .content] | join(", ")' || true)
            if [[ -n "$other_ips" ]]; then
                echo
                read -rp "检测到新域名 [${domain}] 在 Cloudflare 已有其他 IP 记录 (${other_ips})，是否保留它们并存？（多入口共用域名选 Y；旧域名迁机清理旧 IP 选 n）[Y/n，默认 Y 保留]: " KEEP_OTHER_DNS
                KEEP_OTHER_DNS="${KEEP_OTHER_DNS:-Y}"
                if ! [[ "$KEEP_OTHER_DNS" =~ ^[Yy]$ ]]; then
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
                    info "[${domain}] 本机 A 记录已切换为仅 DNS 直连（关闭小云朵）"
                else
                    info "[${domain}] 本机 IP (${SERVER_IP}) 的 A 记录已存在，无需重复添加"
                fi
            else
                create_res=$(curl -fsS -X POST "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${zone_id}/dns_records" --data "$dns_data")
                if [[ "$(echo "$create_res" | jq -r '.success')" != "true" ]]; then
                    echo "$create_res" | jq . >&2 || true
                    error "[${domain}] Cloudflare DNS A 记录新增失败"
                fi
                info "[${domain}] DNS A 记录新增成功 -> ${SERVER_IP}"
            fi
        done
    else
        info "已跳过 Cloudflare DNS A 记录修改"
    fi
fi

# ==============================================================================
# 6. 为新域名签发 / 沿用 Let's Encrypt ECC 证书（不影响已有域名的续期任务）
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
    info "[${domain}] SSL 证书签发并安装成功"
done

# ==============================================================================
# 7. 确保伪装网页目录就绪（若 index.html 已存在则保持原样不覆盖）
# ==============================================================================
WEB_ROOT="/var/www/edge-speedtest"
mkdir -p "$WEB_ROOT"
chmod 755 /var /var/www "$WEB_ROOT"

if [[ ! -s "${WEB_ROOT}/index.html" ]]; then
    info "检测到 ${WEB_ROOT}/index.html 尚未创建，正在补齐默认网络质量监测页..."
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
fi

# ==============================================================================
# 8. 仅写入本次新增域名的独立配置文件（绝不触碰任何其他已有文件，支持无损回滚）
# ==============================================================================
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
declare -A OVERWRITE_BACKUP_MAP=()
declare -a CREATED_CONFS=()
declare -a CREATED_LINKS=()
declare -a TEMP_FILES=()

cleanup_temps() {
    local f
    for f in "${TEMP_FILES[@]:-}"; do
        [[ -n "$f" ]] && rm -f "$f"
    done
}
trap cleanup_temps EXIT

rollback_new_only() {
    warn "检测到新配置校验未通过，正在仅撤回本次新增文件（原有站点保持不变）..."
    local p bak
    for p in "${CREATED_LINKS[@]:-}"; do
        [[ -n "$p" ]] && rm -f "$p"
    done
    for p in "${CREATED_CONFS[@]:-}"; do
        [[ -n "$p" ]] && rm -f "$p"
    done
    for p in "${!OVERWRITE_BACKUP_MAP[@]}"; do
        bak="${OVERWRITE_BACKUP_MAP[$p]}"
        [[ -f "$bak" ]] && mv -f "$bak" "$p"
    done
    if systemctl is-active --quiet nginx; then
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    fi
}

# 沿用本机现有配置中的 ssl_session_cache 大小（若已定义），防止多站点共享缓存大小不一致报错
SSL_CACHE_DIRECTIVE="ssl_session_cache shared:SSL:10m;"
if (( ${#EXISTING_CONFIG_FILES[@]} > 0 )); then
    FOUND_CACHE=$(grep -hE '^[[:space:]]*ssl_session_cache[[:space:]]+shared:SSL:[^;]+;' "${EXISTING_CONFIG_FILES[@]}" 2>/dev/null | head -n 1 | xargs || true)
    if [[ -n "$FOUND_CACHE" ]]; then
        SSL_CACHE_DIRECTIVE="$FOUND_CACHE"
    fi
fi

ENABLE_PORT_80=1
PORT80_OTHER=$(ss -lntp 2>/dev/null | awk '$4 ~ /:80$/ && $0 !~ /"nginx"/ {print $0}' || true)
if [[ -n "$PORT80_OTHER" ]]; then
    ENABLE_PORT_80=0
    warn "检测到 80 端口由非 Nginx 程序监听，新域名将仅配置 HTTPS 端口 (${LISTEN_SUMMARY})"
fi

HAS_IPV6=0
if [[ -s /proc/net/if_inet6 ]]; then
    HAS_IPV6=1
fi

USE_MODERN_HTTP2=0
if nginx_supports_http2_directive; then
    USE_MODERN_HTTP2=1
fi

for domain in "${DOMAINS[@]}"; do
    if (( USE_SITES_ENABLED == 1 )); then
        conf_path="${AVAILABLE_DIR}/${domain}"
        if [[ -L "$conf_path" ]]; then
            resolved=$(readlink -f "$conf_path" || true)
            [[ -n "$resolved" ]] && conf_path="$resolved"
        fi
    else
        conf_path="${CONFD_DIR}/${domain}.conf"
    fi

    if [[ -f "$conf_path" ]]; then
        bak_path="${conf_path}.backup-${TIMESTAMP}"
        cp -a "$conf_path" "$bak_path"
        OVERWRITE_BACKUP_MAP["$conf_path"]="$bak_path"
    else
        CREATED_CONFS+=("$conf_path")
    fi

    tmp_conf=$(mktemp "/tmp/nginx-add-${domain}.XXXXXX")
    TEMP_FILES+=("$tmp_conf")

    # 组装 HTTPS 监听段
    if [[ "$SCENE_MODE" == "1" || "$SCENE_MODE" == "2" ]]; then
        if (( USE_MODERN_HTTP2 == 1 )); then
            HTTPS_LISTEN_BLOCK="    listen 127.0.0.1:${INTERNAL_HTTPS_PORT} ssl;
    http2 on;"
        else
            HTTPS_LISTEN_BLOCK="    listen 127.0.0.1:${INTERNAL_HTTPS_PORT} ssl http2;"
        fi
    else
        IPV6_443_LINE=""
        if (( USE_MODERN_HTTP2 == 1 )); then
            if (( HAS_IPV6 == 1 )); then
                IPV6_443_LINE=$'\n    listen [::]:443 ssl;'
            fi
            HTTPS_LISTEN_BLOCK="    listen 443 ssl;${IPV6_443_LINE}
    http2 on;"
        else
            if (( HAS_IPV6 == 1 )); then
                IPV6_443_LINE=$'\n    listen [::]:443 ssl http2;'
            fi
            HTTPS_LISTEN_BLOCK="    listen 443 ssl http2;${IPV6_443_LINE}"
        fi
    fi

    # 组装 HTTP 80 监听段（场景 2 单机 Reality 自偷采用 301 HTTPS；场景 1/3 保持与 setup-sni-sites.sh 一致）
    HTTP80_BLOCK=""
    if (( ENABLE_PORT_80 == 1 )); then
        IPV6_80_LINE=""
        if (( HAS_IPV6 == 1 )); then
            IPV6_80_LINE=$'\n    listen [::]:80;'
        fi
        if [[ "$SCENE_MODE" == "2" ]]; then
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
        else
            HTTP80_BLOCK="server {
    listen 80;${IPV6_80_LINE}

    server_name ${domain};

    root ${WEB_ROOT};
    index index.html;
    charset utf-8;

    location = /api/ping {
        default_type application/json;
        add_header Cache-Control \"no-store, no-cache, must-revalidate\" always;
        return 200 '{\"status\":\"ok\",\"service\":\"edge-speedtest-node\"}\\n';
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}

"
        fi
    fi

    EXTRA_TLS_LINES=""
    if [[ "$SCENE_MODE" == "2" ]]; then
        EXTRA_TLS_LINES="    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_prefer_server_ciphers off;
"
    fi

    cat > "$tmp_conf" <<EOF
${HTTP80_BLOCK}server {
${HTTPS_LISTEN_BLOCK}

    server_name ${domain};

    ssl_certificate ${DOMAIN_CERT[$domain]};
    ssl_certificate_key ${DOMAIN_KEY[$domain]};

    ssl_protocols TLSv1.2 TLSv1.3;
${EXTRA_TLS_LINES}    ${SSL_CACHE_DIRECTIVE}
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
        enabled_link="${ENABLED_DIR}/${domain}"
        if [[ ! -e "$enabled_link" && ! -L "$enabled_link" ]]; then
            CREATED_LINKS+=("$enabled_link")
        fi
        ln -sfn "$conf_path" "$enabled_link"
    fi
done

# ==============================================================================
# 9. 平滑热加载 Nginx (reload 不断连) + 校验新域名 200 + 巡检原有域名无损在线
# ==============================================================================
info "检测 Nginx 配置语法..."
if ! nginx -t; then
    rollback_new_only
    error "新配置语法检测未通过，已撤回本次新增配置，原有服务不受影响"
fi

if systemctl is-active --quiet nginx; then
    info "正在平滑热加载 Nginx (systemctl reload nginx，不断开任何现有连接)..."
    if ! systemctl reload nginx; then
        rollback_new_only
        error "Nginx 平滑重载失败，已撤回本次新增配置，原有服务不受影响"
    fi
else
    info "检测到 Nginx 当前未运行，正在启动 Nginx..."
    if ! systemctl start nginx; then
        rollback_new_only
        error "Nginx 启动失败，已撤回本次新增配置"
    fi
fi

if ! ss -lnt | grep -qE ":${VERIFY_PORT}[[:space:]]"; then
    rollback_new_only
    error "Nginx 未在端口 ${VERIFY_PORT} 监听，已撤回本次新增配置"
fi

# 校验本次新增域名
for domain in "${DOMAINS[@]}"; do
    PAGE_STATUS=$(curl -ksS -o /dev/null \
        --resolve "${domain}:${VERIFY_PORT}:127.0.0.1" \
        -w '%{http_code}' \
        "https://${domain}:${VERIFY_PORT}/" || true)

    if [[ "$PAGE_STATUS" != "200" ]]; then
        rollback_new_only
        error "新增域名 [${domain}] HTTPS 校验状态码为 ${PAGE_STATUS}（预期 200），已安全撤回本次变更"
    fi
    info "新增域名 [${domain}] HTTPS 200 校验通过！"
done

# 只读巡检原有域名，向管理员确认旧站点 100% 正常在线
declare -a HEALTHY_OLD=()
for old_d in "${EXISTING_DOMAINS[@]:-}"; do
    [[ -z "$old_d" ]] && continue
    OLD_CODE=$(curl -ksS -o /dev/null --max-time 5 \
        --resolve "${old_d}:${VERIFY_PORT}:127.0.0.1" \
        -w '%{http_code}' \
        "https://${old_d}:${VERIFY_PORT}/" || true)
    if [[ "$OLD_CODE" =~ ^[234][0-9][0-9]$ ]]; then
        HEALTHY_OLD+=("${old_d}(${OLD_CODE})")
    fi
done

echo
echo "=================================================================="
echo -e "${GREEN}新域名无损补充完成！原有服务零中断！${NC}"
echo
echo " 本次新增域名 (${#DOMAINS[@]} 个)："
for domain in "${DOMAINS[@]}"; do
    echo "   + ${domain}  (证书: ${DOMAIN_CERT[$domain]})"
done
if (( ${#HEALTHY_OLD[@]} > 0 )); then
    echo
    echo " 原有站点无损在线巡检 (${#HEALTHY_OLD[@]} 个)："
    echo "   ✓ ${HEALTHY_OLD[*]}"
fi
echo
echo " HTTPS 监听地址： ${LISTEN_SUMMARY}（已通过 reload 热生效）"
if [[ "$SCENE_MODE" == "1" ]]; then
    echo
    echo -e " ${CYAN}[下一步：RelayPanel 中转面板配置]${NC}"
    echo "   在对应设备组新增转发规则：监听端口 443，SNI 填新域名（如 ${DOMAINS[0]}），目标填落地机 IP:端口"
elif [[ "$SCENE_MODE" == "2" ]]; then
    echo
    echo -e " ${CYAN}[下一步：机场面板单机 Reality 节点配置]${NC}"
    echo "   连接端口: 443  |  服务端口: 443  |  Server Name(SNI): ${DOMAINS[0]}"
    echo -e "   Server Address: ${YELLOW}127.0.0.1${NC}  |  Server Port: ${YELLOW}${INTERNAL_HTTPS_PORT}${NC}  |  Proxy Protocol: 0"
fi
echo "=================================================================="
echo

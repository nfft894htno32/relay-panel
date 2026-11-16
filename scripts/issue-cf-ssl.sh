#!/usr/bin/env bash

set -Eeuo pipefail

# ==============================================================================
# 独立 Cloudflare DNS-01 SSL 证书签发与自动续期脚本
#
# 定位与特性：
#   - 仅申请并定期续期 Let's Encrypt SSL 证书，不安装 Nginx/Caddy/Certbot/Python
#   - 不创建任何网页目录，不监听或占用 80 / 443 等任何端口
#   - 不修改 Cloudflare A / AAAA 解析记录（仅在签发与续期时临时创建并清理 _acme-challenge TXT）
#   - 默认安装到标准路径：
#       /etc/letsencrypt/live/<域名>/fullchain.pem
#       /etc/letsencrypt/live/<域名>/privkey.pem
#   - 自动配置 acme.sh cron 定时任务，证书到期前自动无感续期并覆盖上述文件
# ==============================================================================

CF_API_TOKEN="${CF_API_TOKEN:-${CF_Token:-}}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
KEY_TYPE="${KEY_TYPE:-ec-256}"
DNS_SLEEP="${DNS_SLEEP:-20}"
RELOAD_CMD="${RELOAD_CMD:-}"
FORCE_ISSUE=0
ASSUME_YES=0

ACME_HOME="/root/.acme.sh"
ACME_SH="${ACME_HOME}/acme.sh"
ACME_ACCOUNT_CONF="${ACME_HOME}/account.conf"
CF_CRED_BACKUP="/etc/letsencrypt/cloudflare.ini"
CF_API="https://api.cloudflare.com/client/v4"

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
NC="\033[0m"

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[×]${NC} $*" >&2; exit 1; }

print_help() {
    cat <<'EOF'
独立 Cloudflare DNS-01 SSL 证书签发与自动续期脚本（零多余安装）

用法:
  bash issue-cf-ssl.sh [选项] [域名...]

选项:
  -d, --domain <域名>      指定域名（支持逗号/空格分隔，或多次传 -d；支持泛域名 *.example.com）
  -t, --token <Token>      Cloudflare API Token（需 Zone:Read + DNS:Edit 权限；也可通过 CF_API_TOKEN 传入）
      --zone-id <ZoneID>   可选，显式指定 Cloudflare Zone ID（单 Zone 最小权限 Token 可传此项）
      --key-type <类型>    密钥算法：ec-256（默认） / ec-384 / rsa-2048
      --dnssleep <秒数>    DNS TXT 生效等待秒数，默认 20；设为 0 则由 acme.sh 自动轮询公网 DNS
      --reload-cmd <命令>  证书安装/续期成功后的回调命令（如 "systemctl restart xray"），默认不重启任何服务
  -f, --force              即使已有有效证书仍强制重新签发
  -y, --yes                非交互模式（自动沿用本机已存 Token，遇到有效现有证书跳过重签）
  -h, --help               显示此帮助信息

输出路径:
  /etc/letsencrypt/live/<域名>/fullchain.pem
  /etc/letsencrypt/live/<域名>/privkey.pem
  （若申请 *.example.com，标准路径同样为 /etc/letsencrypt/live/example.com/）

示例:
  1) 交互式运行:
     bash issue-cf-ssl.sh

  2) 单命令非交互申请指定域名:
     bash issue-cf-ssl.sh -d region-tw02-speedtestapi.howfastyourspeed.com -t '你的CF_Token' -y

  3) 续期后自动重启某个节点服务:
     bash issue-cf-ssl.sh -d region-tw02-speedtestapi.howfastyourspeed.com -t '你的CF_Token' \
       --reload-cmd "systemctl restart v2node || true" -y
EOF
}

declare -a RAW_DOMAIN_ITEMS=()

while (( $# > 0 )); do
    case "$1" in
        -d|--domain)
            [[ $# -lt 2 || -z "${2:-}" ]] && error "参数 $1 缺少域名值"
            RAW_DOMAIN_ITEMS+=("$2")
            shift 2
            ;;
        -t|--token)
            [[ $# -lt 2 || -z "${2:-}" ]] && error "参数 $1 缺少 API Token 值"
            CF_API_TOKEN="$2"
            shift 2
            ;;
        --zone-id)
            [[ $# -lt 2 || -z "${2:-}" ]] && error "参数 $1 缺少 Zone ID 值"
            CF_ZONE_ID="$2"
            shift 2
            ;;
        --key-type)
            [[ $# -lt 2 || -z "${2:-}" ]] && error "参数 $1 缺少密钥类型"
            KEY_TYPE="$2"
            shift 2
            ;;
        --dnssleep)
            [[ $# -lt 2 || -z "${2:-}" ]] && error "参数 $1 缺少等待秒数"
            DNS_SLEEP="$2"
            shift 2
            ;;
        --reload-cmd)
            [[ $# -lt 2 ]] && error "参数 $1 缺少命令内容"
            RELOAD_CMD="$2"
            shift 2
            ;;
        -f|--force)
            FORCE_ISSUE=1
            shift
            ;;
        -y|--yes)
            ASSUME_YES=1
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        --)
            shift
            while (( $# > 0 )); do
                RAW_DOMAIN_ITEMS+=("$1")
                shift
            done
            ;;
        -*)
            error "未知参数：$1（可使用 --help 查看支持的参数）"
            ;;
        *)
            RAW_DOMAIN_ITEMS+=("$1")
            shift
            ;;
    esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    error "请使用 root 用户运行此脚本"
fi

prompt_input() {
    local prompt_text="$1"
    local target_var="$2"
    local val=""

    if [[ -t 0 ]]; then
        IFS= read -rp "$prompt_text" val || error "读取用户输入失败"
    elif [[ -r /dev/tty ]]; then
        IFS= read -rp "$prompt_text" val < /dev/tty || error "从终端读取用户输入失败"
    else
        error "当前处于非交互环境，请通过 -d / -t / -y 等参数传入所需配置"
    fi

    printf -v "$target_var" '%s' "$val"
}

prompt_secret() {
    local prompt_text="$1"
    local target_var="$2"
    local val=""

    if [[ -t 0 ]]; then
        IFS= read -rsp "$prompt_text" val || error "读取敏感输入失败"
        echo
    elif [[ -r /dev/tty ]]; then
        IFS= read -rsp "$prompt_text" val < /dev/tty || error "从终端读取敏感输入失败"
        echo > /dev/tty
    else
        error "当前处于非交互环境，请通过 -t 或环境变量 CF_API_TOKEN 传入 Cloudflare API Token"
    fi

    printf -v "$target_var" '%s' "$val"
}

# ==============================================================================
# 1. 基础参数校验与最小依赖检查（绝不安装 Nginx/Certbot/Python）
# ==============================================================================
case "$KEY_TYPE" in
    ec-256|ec-384|rsa-2048) ;;
    *) error "不支持的密钥类型：${KEY_TYPE}（可选：ec-256、ec-384、rsa-2048）" ;;
esac

if ! [[ "$DNS_SLEEP" =~ ^[0-9]+$ ]]; then
    error "--dnssleep 必须是非负整数，当前值：${DNS_SLEEP}"
fi

ensure_dependencies() {
    local missing=()
    command -v curl >/dev/null 2>&1    || missing+=("curl")
    command -v jq >/dev/null 2>&1      || missing+=("jq")
    command -v openssl >/dev/null 2>&1 || missing+=("openssl")
    command -v crontab >/dev/null 2>&1 || missing+=("cron")

    if (( ${#missing[@]} > 0 )); then
        info "正在安装最小必要依赖：${missing[*]}（不安装任何 Web 服务或代理）..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl jq ca-certificates openssl cron
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q curl jq ca-certificates openssl cronie
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q curl jq ca-certificates openssl cronie
        elif command -v apk >/dev/null 2>&1; then
            apk add --no-cache curl jq ca-certificates openssl dcron
        else
            error "未识别的包管理器，请先手动安装：${missing[*]}"
        fi
    fi

    systemctl enable --now cron >/dev/null 2>&1 \
        || systemctl enable --now crond >/dev/null 2>&1 \
        || rc-service dcron start >/dev/null 2>&1 \
        || service cron start >/dev/null 2>&1 \
        || true
}

ensure_dependencies

# ==============================================================================
# 2. 解析并规范化目标域名（支持普通域名与泛域名 *.example.com）
# ==============================================================================
echo
echo -e "${CYAN}==================================================================${NC}"
echo -e "${CYAN}  Cloudflare DNS-01 独立 SSL 证书申请与自动续期工具（极简纯净版） ${NC}"
echo -e "${CYAN}==================================================================${NC}"

if (( ${#RAW_DOMAIN_ITEMS[@]} == 0 )); then
    if (( ASSUME_YES == 1 )); then
        error "非交互模式下必须通过 -d 或位置参数指定至少一个域名"
    fi
    echo
    RAW_INPUT=""
    prompt_input "请输入要申请证书的域名（多个域名用空格或逗号分隔，支持泛域名如 *.example.com）: " RAW_INPUT
    RAW_DOMAIN_ITEMS+=("$RAW_INPUT")
fi

declare -a CERT_NAMES=()
declare -A CERT_IS_WILDCARD=()

add_target_domain() {
    local raw="$1"
    local d is_wildcard=0 cert_name

    d=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | xargs)
    d="${d#http://}"
    d="${d#https://}"
    d="${d%%/*}"
    d="${d%.}"
    [[ -z "$d" ]] && return 0

    if [[ "$d" =~ ^\*\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
        cert_name="${d#\*.}"
        is_wildcard=1
    elif [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
        cert_name="$d"
        is_wildcard=0
    else
        error "域名格式不正确：${raw}"
    fi

    if [[ -z "${CERT_IS_WILDCARD[$cert_name]+x}" ]]; then
        CERT_IS_WILDCARD[$cert_name]="$is_wildcard"
        CERT_NAMES+=("$cert_name")
    elif (( is_wildcard == 1 )); then
        CERT_IS_WILDCARD[$cert_name]=1
    fi
}

for raw_item in "${RAW_DOMAIN_ITEMS[@]}"; do
    raw_item="${raw_item//,/ }"
    declare -a SPLIT_ITEMS=()
    read -r -a SPLIT_ITEMS <<< "$raw_item"
    for item in "${SPLIT_ITEMS[@]}"; do
        add_target_domain "$item"
    done
done

if (( ${#CERT_NAMES[@]} == 0 )); then
    error "未解析到任何有效域名"
fi

# ==============================================================================
# 3. 检查现有证书及 acme.sh 自动续期托管状态
# ==============================================================================
cert_is_valid_seconds() {
    local cert_file="$1"
    local key_file="$2"
    local min_secs="$3"
    local pub1 pub2

    [[ -s "$cert_file" && -s "$key_file" ]] || return 1
    openssl x509 -in "$cert_file" -noout -checkend "$min_secs" >/dev/null 2>&1 || return 1

    pub1=$(openssl x509 -in "$cert_file" -noout -pubkey 2>/dev/null || true)
    pub2=$(openssl pkey -in "$key_file" -pubout 2>/dev/null || true)
    [[ -n "$pub1" && "$pub1" == "$pub2" ]]
}

cert_is_valid_30d() {
    cert_is_valid_seconds "$1" "$2" 2592000
}

is_managed_by_acme() {
    local cert_name="$1"
    if [[ "$KEY_TYPE" == "rsa-2048" ]]; then
        [[ -f "${ACME_HOME}/${cert_name}/${cert_name}.conf" ]]
    else
        [[ -f "${ACME_HOME}/${cert_name}_ecc/${cert_name}.conf" ]]
    fi
}

cert_covers_requested_san() {
    local cert_file="$1"
    local cert_name="$2"
    local is_wildcard="$3"

    if (( is_wildcard == 1 )); then
        openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -Fq "DNS:*.${cert_name}"
    else
        return 0
    fi
}

declare -a TO_ISSUE_LIST=()

for cert_name in "${CERT_NAMES[@]}"; do
    cert_path="/etc/letsencrypt/live/${cert_name}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${cert_name}/privkey.pem"
    is_wc="${CERT_IS_WILDCARD[$cert_name]}"

    if (( FORCE_ISSUE == 0 )) \
        && cert_is_valid_30d "$cert_path" "$key_path" \
        && is_managed_by_acme "$cert_name" \
        && cert_covers_requested_san "$cert_path" "$cert_name" "$is_wc"; then
        end_date=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2 || true)
        if (( ASSUME_YES == 1 )); then
            info "[${cert_name}] 已有有效证书（剩余 >30 天，到期: ${end_date}）且已纳入续期，跳过重复签发"
            continue
        fi
        echo
        read_ans=""
        prompt_input "检测到 [${cert_name}] 已有有效证书（剩余 >30 天，到期: ${end_date}）且已纳入自动续期，是否强制重新签发？[y/N，默认 N]: " read_ans
        read_ans="${read_ans:-N}"
        if [[ "$read_ans" =~ ^[Yy]$ ]]; then
            TO_ISSUE_LIST+=("$cert_name")
        else
            info "[${cert_name}] 保留现有证书，稍后同步确认定时自动续期任务"
        fi
    else
        TO_ISSUE_LIST+=("$cert_name")
    fi
done

# ==============================================================================
# 4. 读取、输入并校验 Cloudflare API Token（仅在需要签发或显式传入时校验）
# ==============================================================================
extract_saved_cf_token() {
    local token=""
    if [[ -f "$CF_CRED_BACKUP" ]]; then
        token=$(awk -F'=' '/^[[:space:]]*dns_cloudflare_api_token[[:space:]]*=/ {v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); gsub(/^[\x27"]|[\x27"]$/, "", v); print v; exit}' "$CF_CRED_BACKUP" || true)
    fi
    if [[ -z "$token" && -f "$ACME_ACCOUNT_CONF" ]]; then
        token=$(awk -F'=' '/^SAVED_CF_Token=/ {v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); gsub(/^[\x27"]|[\x27"]$/, "", v); print v; exit}' "$ACME_ACCOUNT_CONF" || true)
    fi
    if [[ -z "$token" && -d "$ACME_HOME" ]]; then
        shopt -s nullglob
        local domain_conf
        for domain_conf in "${ACME_HOME}"/*/*.conf; do
            [[ -f "$domain_conf" ]] || continue
            token=$(awk -F'=' '/^SAVED_CF_Token=/ {v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); gsub(/^[\x27"]|[\x27"]$/, "", v); print v; exit}' "$domain_conf" || true)
            [[ -n "$token" ]] && break
        done
        shopt -u nullglob
    fi
    printf '%s' "$token"
}

declare -a CF_AUTH_HEADER=()

if (( ${#TO_ISSUE_LIST[@]} > 0 )) || [[ -n "$CF_API_TOKEN" ]]; then
    if [[ -z "$CF_API_TOKEN" ]]; then
        SAVED_TOKEN=$(extract_saved_cf_token)
        if [[ -n "$SAVED_TOKEN" ]]; then
            if (( ASSUME_YES == 1 )); then
                CF_API_TOKEN="$SAVED_TOKEN"
                info "已自动沿用本机保存的 Cloudflare API Token"
            else
                echo
                USE_SAVED=""
                prompt_input "检测到本机已保存的 Cloudflare API Token，是否直接沿用？[Y/n，默认 Y]: " USE_SAVED
                USE_SAVED="${USE_SAVED:-Y}"
                if [[ "$USE_SAVED" =~ ^[Yy]$ ]]; then
                    CF_API_TOKEN="$SAVED_TOKEN"
                fi
            fi
        fi

        if [[ -z "$CF_API_TOKEN" ]]; then
            echo
            prompt_secret "请输入 Cloudflare API Token（需 Zone:Read + DNS:Edit 权限，输入不回显）: " CF_API_TOKEN
        fi
    fi

    CF_API_TOKEN=$(printf '%s' "$CF_API_TOKEN" | xargs)
    if [[ -z "$CF_API_TOKEN" ]]; then
        error "Cloudflare API Token 不能为空"
    fi

    CF_AUTH_HEADER=(
        -H "Authorization: Bearer ${CF_API_TOKEN}"
        -H "Content-Type: application/json"
    )

    info "正在验证 Cloudflare API Token ..."
    if [[ -n "$CF_ZONE_ID" ]]; then
        CF_VERIFY=$(curl -fsS --max-time 15 "${CF_AUTH_HEADER[@]}" "${CF_API}/zones/${CF_ZONE_ID}/dns_records?per_page=1" 2>/dev/null || true)
    else
        CF_VERIFY=$(curl -fsS --max-time 15 "${CF_AUTH_HEADER[@]}" "${CF_API}/zones?per_page=1" 2>/dev/null || true)
    fi

    if [[ "$(printf '%s' "$CF_VERIFY" | jq -r '.success // false' 2>/dev/null)" != "true" ]]; then
        error "Cloudflare API Token 验证失败，请确认权限包含 Zone -> Zone -> Read 与 Zone -> DNS -> Edit（单 Zone Token 请配合 --zone-id）"
    fi
    info "Cloudflare API Token 验证通过"

    mkdir -p /etc/letsencrypt
    chmod 755 /etc/letsencrypt
    (
        umask 077
        printf 'dns_cloudflare_api_token = %s\n' "$CF_API_TOKEN" > "$CF_CRED_BACKUP"
    )
    chmod 600 "$CF_CRED_BACKUP"
fi

# ==============================================================================
# 5. 安装/确认 acme.sh、定位 Zone ID、签发并安装证书到标准路径
# ==============================================================================
ensure_acme_sh() {
    local installer="/tmp/acme-install.$$.sh"
    if [[ ! -x "$ACME_SH" || ! -f "${ACME_HOME}/dnsapi/dns_cf.sh" ]]; then
        info "正在安装轻量级 ACME 客户端 acme.sh ..."
        if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 120 \
            https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o "$installer"; then
            error "acme.sh 下载失败，请检查服务器是否可访问 raw.githubusercontent.com"
        fi
        chmod 700 "$installer"
        sh "$installer" --install-online --home "$ACME_HOME" --config-home "$ACME_HOME" --nocron --noprofile
        rm -f "$installer"
    fi
    chmod 700 "$ACME_HOME"
    "$ACME_SH" --set-default-ca --server letsencrypt --home "$ACME_HOME" --config-home "$ACME_HOME" >/dev/null 2>&1 || true
    "$ACME_SH" --install-cronjob --home "$ACME_HOME" --config-home "$ACME_HOME" >/dev/null
}

declare -A ZONE_CACHE=()

find_zone_id() {
    local domain="$1"
    if [[ -n "$CF_ZONE_ID" ]]; then
        printf '%s' "$CF_ZONE_ID"
        return 0
    fi

    local current="$domain"
    while [[ "$current" == *.* ]]; do
        if [[ -n "${ZONE_CACHE[$current]:-}" ]]; then
            printf '%s' "${ZONE_CACHE[$current]}"
            return 0
        fi
        local resp found_id
        resp=$(curl -fsS --max-time 15 "${CF_AUTH_HEADER[@]}" "${CF_API}/zones?name=${current}&status=active" 2>/dev/null || true)
        found_id=$(printf '%s' "$resp" | jq -r '.result[0].id // empty' 2>/dev/null || true)
        if [[ -n "$found_id" ]]; then
            ZONE_CACHE[$current]="$found_id"
            printf '%s' "$found_id"
            return 0
        fi
        current="${current#*.}"
    done
    return 1
}

if (( ${#TO_ISSUE_LIST[@]} > 0 )); then
    ensure_acme_sh

    acme_keylength="$KEY_TYPE"
    declare -a ecc_args=(--ecc)
    if [[ "$KEY_TYPE" == "rsa-2048" ]]; then
        acme_keylength="2048"
        ecc_args=()
    fi

    declare -a dnssleep_args=()
    if (( DNS_SLEEP > 0 )); then
        dnssleep_args=(--dnssleep "$DNS_SLEEP")
    fi

    declare -a force_args=()
    if (( FORCE_ISSUE == 1 )); then
        force_args=(--force)
    fi

    effective_reload_cmd="${RELOAD_CMD:-:}"

    for cert_name in "${TO_ISSUE_LIST[@]}"; do
        is_wc="${CERT_IS_WILDCARD[$cert_name]}"
        zone_id=$(find_zone_id "$cert_name" || true)
        if [[ -z "$zone_id" ]]; then
            error "[${cert_name}] 无法自动匹配到所属 Cloudflare Zone，请确认域名已托管在当前账号下，或使用 --zone-id 显式指定"
        fi

        declare -a domain_args=(-d "$cert_name")
        display_names="$cert_name"
        if (( is_wc == 1 )); then
            domain_args+=(-d "*.${cert_name}")
            display_names="${cert_name}, *.${cert_name}"
        fi

        info "[${cert_name}] 正在通过 Cloudflare DNS-01 申请 Let's Encrypt 证书 (${KEY_TYPE}) [${display_names}] ..."

        export CF_Token="$CF_API_TOKEN"
        export CF_Zone_ID="$zone_id"

        set +e
        "$ACME_SH" --issue \
            --home "$ACME_HOME" \
            --config-home "$ACME_HOME" \
            --server letsencrypt \
            --dns dns_cf \
            "${dnssleep_args[@]}" \
            --keylength "$acme_keylength" \
            "${force_args[@]}" \
            "${domain_args[@]}"
        acme_rc=$?
        set -e

        if [[ "$acme_rc" -ne 0 && "$acme_rc" -ne 2 ]]; then
            unset CF_Token CF_Zone_ID
            error "[${cert_name}] Let's Encrypt SSL 证书申请失败（退出码 ${acme_rc}）"
        fi

        cert_dir="/etc/letsencrypt/live/${cert_name}"
        cert_path="${cert_dir}/fullchain.pem"
        key_path="${cert_dir}/privkey.pem"

        mkdir -p /etc/letsencrypt /etc/letsencrypt/live "$cert_dir"
        chmod 755 /etc/letsencrypt /etc/letsencrypt/live "$cert_dir"
        [[ -L "$cert_path" ]] && rm -f "$cert_path"
        [[ -L "$key_path" ]]  && rm -f "$key_path"

        if ! "$ACME_SH" --install-cert \
            --home "$ACME_HOME" \
            --config-home "$ACME_HOME" \
            "${ecc_args[@]}" \
            -d "$cert_name" \
            --key-file "$key_path" \
            --fullchain-file "$cert_path" \
            --reloadcmd "$effective_reload_cmd"; then
            unset CF_Token CF_Zone_ID
            error "[${cert_name}] 安装证书到 ${cert_dir} 失败"
        fi

        unset CF_Token CF_Zone_ID
        chmod 644 "$cert_path"
        chmod 600 "$key_path"

        if ! cert_is_valid_seconds "$cert_path" "$key_path" 86400; then
            error "[${cert_name}] 证书文件校验未通过，请检查 ${cert_path} 与 ${key_path}"
        fi

        info "[${cert_name}] 证书签发并安装完成"
    done
fi

# ==============================================================================
# 6. 确保自动续期定时任务（cron）持续有效
# ==============================================================================
if [[ -x "$ACME_SH" ]]; then
    chmod 700 "$ACME_HOME"
    "$ACME_SH" --install-cronjob --home "$ACME_HOME" --config-home "$ACME_HOME" >/dev/null 2>&1 || true

    if ! (crontab -l 2>/dev/null || true) | grep -Fq "acme.sh --cron"; then
        cron_line="18 3 * * * \"${ACME_HOME}\"/acme.sh --cron --home \"${ACME_HOME}\" > /dev/null"
        (
            crontab -l 2>/dev/null || true
            printf '%s\n' "$cron_line"
        ) | crontab -
        info "已自动补齐 acme.sh 每日定期续期 cron 任务"
    fi
fi

# ==============================================================================
# 7. 输出证书路径与自动续期状态汇总
# ==============================================================================
CRON_ENTRY=$((crontab -l 2>/dev/null || true) | grep -F "acme.sh --cron" | head -n 1 || true)

echo
echo "=================================================================="
echo -e "${GREEN}SSL 证书就绪！未安装多余 Web 服务，未占用任何端口。${NC}"
echo
for cert_name in "${CERT_NAMES[@]}"; do
    cert_path="/etc/letsencrypt/live/${cert_name}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${cert_name}/privkey.pem"
    end_date=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "未知")
    echo " 域名：${cert_name}$( (( CERT_IS_WILDCARD[$cert_name] == 1 )) && printf '（含 *.%s）' "$cert_name" )"
    echo "   fullchain.pem : ${cert_path}"
    echo "   privkey.pem   : ${key_path}"
    echo "   有效期至      : ${end_date}"
    echo
done
if [[ -n "$CRON_ENTRY" ]]; then
    echo " 自动续期计划（cron）："
    echo "   ${CRON_ENTRY}"
else
    warn "未检测到 crontab 中的 acme.sh --cron 条目，请手动检查 crontab -l"
fi
echo
echo " 手动立即测试全部证书续期命令："
echo "   \"${ACME_SH}\" --cron --home \"${ACME_HOME}\" --force"
echo "=================================================================="
echo

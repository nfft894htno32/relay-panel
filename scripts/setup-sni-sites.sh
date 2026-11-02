#!/usr/bin/env bash

set -Eeuo pipefail

# ==============================================================================
# 多域名 Cloudflare DNS 解析 + SSL 证书自动签发 + Nginx 200 测速伪装站一键部署脚本
#
# 核心能力：
#   1. 支持一次输入多个域名（空格或逗号分隔，支持跨不同主域名 Zone）
#   2. 通过 Cloudflare API Token 自动添加/更新 A / AAAA 解析记录（自动关闭小黄云代理）
#   3. 通过 Certbot + Cloudflare DNS-01 自动批量签发/复用 SSL 证书并配置自动续期重载
#   4. 默认监听本地 127.0.0.1:10443（把公网 443 腾给 relay-node 多 SNI 分流），亦可选公网 443
#   5. 部署逼真的「边缘节点网络质量测速」静态网页（HTTP 200 OK，含真实 RTT 延迟与吞吐测速）
#   6. 完整备份原有 Nginx 配置，逐域名本机 HTTPS 200 校验，异常时全量自动回滚
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

# ------------------------------------------------------------------------------
# 1. 环境检查与依赖自动安装
# ------------------------------------------------------------------------------
ensure_dependencies() {
    local missing_pkgs=()

    command -v curl >/dev/null 2>&1    || missing_pkgs+=("curl")
    command -v jq >/dev/null 2>&1      || missing_pkgs+=("jq")
    command -v openssl >/dev/null 2>&1 || missing_pkgs+=("openssl")
    command -v ss >/dev/null 2>&1      || missing_pkgs+=("iproute2")
    command -v nginx >/dev/null 2>&1   || missing_pkgs+=("nginx")
    command -v certbot >/dev/null 2>&1 || missing_pkgs+=("certbot")

    # 检查 certbot cloudflare 插件
    if ! command -v certbot >/dev/null 2>&1 || ! certbot plugins 2>/dev/null | grep -qi "dns-cloudflare"; then
        missing_pkgs+=("python3-certbot-dns-cloudflare")
    fi

    if (( ${#missing_pkgs[@]} > 0 )); then
        info "正在自动安装缺失依赖：${missing_pkgs[*]} ..."
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq "${missing_pkgs[@]}"
        else
            error "当前系统非 Debian/Ubuntu，请先手动安装：${missing_pkgs[*]}"
        fi
    fi

    for cmd in nginx systemctl ss curl jq openssl certbot awk grep sed tail cp mv ln readlink date mktemp chmod chown rm dd; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "缺少必要命令：$cmd"
        fi
    done
}

# 检测 Nginx 版本是否 >= 1.25.1（决定使用 `http2 on;` 还是 `listen ... ssl http2;`）
nginx_supports_http2_directive() {
    local ver major minor patch
    ver=$(nginx -v 2>&1 | sed -nE 's/.*nginx\/([0-9]+)\.([0-9]+)\.([0-9]+).*/\1 \2 \3/p')
    if [[ -z "$ver" ]]; then
        return 1
    fi
    read -r major minor patch <<< "$ver"
    if (( major > 1 )) || (( major == 1 && minor > 25 )) || (( major == 1 && minor == 25 && patch >= 1 )); then
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
# 2. 交互式收集域名、端口模式与 Cloudflare 配置
# ------------------------------------------------------------------------------
ensure_dependencies

echo
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}   多域名 SSL 证书签发 + 网络测速伪装站 (HTTP 200) 部署工具   ${NC}"
echo -e "${CYAN}============================================================${NC}"
echo

read -rp "请输入要部署的域名（多个域名用空格或逗号分隔，如 hk1.example.com hk2.example.com）: " RAW_DOMAINS

# 清洗并拆分域名列表
RAW_DOMAINS="${RAW_DOMAINS//,/ }"
declare -a DOMAINS=()
declare -A SEEN_DOMAINS=()

for item in $RAW_DOMAINS; do
    d=$(echo "$item" | tr '[:upper:]' '[:lower:]' | xargs)
    d="${d#http://}"
    d="${d#https://}"
    d="${d%%/*}"
    [[ -z "$d" ]] && continue

    if ! [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
        error "域名格式不正确：$d"
    fi

    if [[ -z "${SEEN_DOMAINS[$d]:-}" ]]; then
        SEEN_DOMAINS[$d]=1
        DOMAINS+=("$d")
    fi
done

if (( ${#DOMAINS[@]} == 0 )); then
    error "未输入任何有效域名"
fi

info "共识别到 ${#DOMAINS[@]} 个域名：${DOMAINS[*]}"

echo
echo "请选择 Nginx HTTPS 监听模式："
echo "  1) 本地回源模式 127.0.0.1:10443 （推荐：将公网 443 留给 relay-node 多 SNI 分流）"
echo "  2) 公网直连模式 0.0.0.0:443 & [::]:443 （Nginx 直接占用公网 443）"
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

# ------------------------------------------------------------------------------
# 3. Cloudflare API Token 读取与校验
# ------------------------------------------------------------------------------
CF_CRED_FILE="/etc/letsencrypt/cloudflare.ini"
CF_TOKEN=""

if [[ -f "$CF_CRED_FILE" ]]; then
    EXISTING_TOKEN=$(awk -F'=' '/dns_cloudflare_api_token/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$CF_CRED_FILE" || true)
    if [[ -n "$EXISTING_TOKEN" ]]; then
        echo
        read -rp "检测到已保存的 Cloudflare API Token (${CF_CRED_FILE})，是否直接沿用？[Y/n]: " USE_EXISTING
        USE_EXISTING="${USE_EXISTING:-Y}"
        if [[ "$USE_EXISTING" =~ ^[Yy]$ ]]; then
            CF_TOKEN="$EXISTING_TOKEN"
        fi
    fi
fi

if [[ -z "$CF_TOKEN" ]]; then
    echo
    read -rsp "请输入 Cloudflare API Token（需具备 Zone:DNS:Edit 权限，输入不回显）: " CF_TOKEN
    echo
    CF_TOKEN=$(echo "$CF_TOKEN" | xargs)
    if [[ -z "$CF_TOKEN" ]]; then
        error "Cloudflare API Token 不能为空"
    fi
fi

info "正在验证 Cloudflare API Token ..."
CF_VERIFY_RESP=$(curl -fsSL -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
    "https://api.cloudflare.com/client/v4/zones?per_page=1" 2>/dev/null || true)

if [[ -z "$CF_VERIFY_RESP" ]] || [[ "$(echo "$CF_VERIFY_RESP" | jq -r '.success // false')" != "true" ]]; then
    error "Cloudflare API Token 验证失败，请检查 Token 是否正确且包含 Zone.DNS 编辑权限"
fi
info "Cloudflare API Token 验证通过"

mkdir -p /etc/letsencrypt
umask 077
cat > "$CF_CRED_FILE" <<EOF
dns_cloudflare_api_token = ${CF_TOKEN}
EOF
chmod 600 "$CF_CRED_FILE"

# ------------------------------------------------------------------------------
# 4. Cloudflare DNS 记录自动添加 / 更新
# ------------------------------------------------------------------------------
detect_public_ip() {
    local family="$1"
    local urls=()
    if [[ "$family" == "4" ]]; then
        urls=("https://api4.ipify.org" "https://ipv4.icanhazip.com" "https://v4.ident.me")
    else
        urls=("https://api6.ipify.org" "https://ipv6.icanhazip.com" "https://v6.ident.me")
    fi
    local ip=""
    for u in "${urls[@]}"; do
        ip=$(curl "-${family}" -fsSL --connect-timeout 4 --max-time 6 "$u" 2>/dev/null | xargs || true)
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 0
}

echo
read -rp "是否自动在 Cloudflare 添加/更新这些域名指向本机的 DNS 解析（仅 DNS 灰云）？[Y/n]: " AUTO_DNS
AUTO_DNS="${AUTO_DNS:-Y}"

declare -A ZONE_CACHE=()

# 查找域名在 Cloudflare 中对应的 Zone ID（按最长后缀逐级匹配并带内存缓存）
find_cf_zone_id() {
    local domain="$1"
    local candidate="$domain"
    while [[ "$candidate" == *.* ]]; do
        if [[ -n "${ZONE_CACHE[$candidate]:-}" ]]; then
            echo "${ZONE_CACHE[$candidate]}"
            return 0
        fi
        local resp zone_id
        resp=$(curl -fsSL -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
            "https://api.cloudflare.com/client/v4/zones?name=${candidate}&status=active" 2>/dev/null || true)
        zone_id=$(echo "$resp" | jq -r '.result[0].id // empty' 2>/dev/null || true)
        if [[ -n "$zone_id" ]]; then
            ZONE_CACHE[$candidate]="$zone_id"
            echo "$zone_id"
            return 0
        fi
        candidate="${candidate#*.}"
    done
    return 1
}

upsert_cf_dns_record() {
    local zone_id="$1"
    local domain="$2"
    local rtype="$3"
    local target_ip="$4"

    local list_resp record_id payload write_resp
    list_resp=$(curl -fsSL -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?type=${rtype}&name=${domain}" 2>/dev/null || true)

    record_id=$(echo "$list_resp" | jq -r '.result[0].id // empty' 2>/dev/null || true)
    payload=$(jq -nc \
        --arg type "$rtype" \
        --arg name "$domain" \
        --arg content "$target_ip" \
        '{type: $type, name: $name, content: $content, ttl: 60, proxied: false}')

    if [[ -n "$record_id" ]]; then
        write_resp=$(curl -fsSL -X PUT \
            -H "Authorization: Bearer ${CF_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "$payload" \
            "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" 2>/dev/null || true)
    else
        write_resp=$(curl -fsSL -X POST \
            -H "Authorization: Bearer ${CF_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "$payload" \
            "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" 2>/dev/null || true)
    fi

    if [[ "$(echo "$write_resp" | jq -r '.success // false')" != "true" ]]; then
        local err_msg
        err_msg=$(echo "$write_resp" | jq -r '.errors[0].message // "未知错误"' 2>/dev/null || echo "未知错误")
        error "Cloudflare DNS ${rtype} 记录更新失败 (${domain})：${err_msg}"
    fi
    info "DNS 已就绪：${domain} [${rtype}] -> ${target_ip} (仅 DNS / 未开代理)"
}

if [[ "$AUTO_DNS" =~ ^[Yy]$ ]]; then
    DETECTED_IPV4=$(detect_public_ip 4)
    DETECTED_IPV6=$(detect_public_ip 6)

    read -rp "确认用于 A 记录的本机 IPv4 地址 [默认 ${DETECTED_IPV4:-跳过}]: " TARGET_IPV4
    TARGET_IPV4="${TARGET_IPV4:-$DETECTED_IPV4}"

    TARGET_IPV6=""
    if [[ -n "$DETECTED_IPV6" ]]; then
        read -rp "检测到本机 IPv6 (${DETECTED_IPV6})，是否同时配置 AAAA 记录？[y/N]: " BIND_V6
        if [[ "${BIND_V6:-N}" =~ ^[Yy]$ ]]; then
            TARGET_IPV6="$DETECTED_IPV6"
        fi
    fi

    if [[ -z "$TARGET_IPV4" && -z "$TARGET_IPV6" ]]; then
        warn "未提供任何目标 IP，跳过 DNS 记录修改"
    else
        for domain in "${DOMAINS[@]}"; do
            zone_id=$(find_cf_zone_id "$domain" || true)
            if [[ -z "$zone_id" ]]; then
                error "在当前 Cloudflare 账号下未找到域名 ${domain} 所属的活跃 Zone"
            fi

            [[ -n "$TARGET_IPV4" ]] && upsert_cf_dns_record "$zone_id" "$domain" "A" "$TARGET_IPV4"
            [[ -n "$TARGET_IPV6" ]] && upsert_cf_dns_record "$zone_id" "$domain" "AAAA" "$TARGET_IPV6"
        done
    fi
fi

# ------------------------------------------------------------------------------
# 5. SSL 证书检查与自动签发（优先沿用有效现有证书，否则 Certbot DNS-01 签发）
# ------------------------------------------------------------------------------
AVAILABLE_DIR="/etc/nginx/sites-available"
ENABLED_DIR="/etc/nginx/sites-enabled"
mkdir -p "$AVAILABLE_DIR" "$ENABLED_DIR"

declare -A DOMAIN_CERT=()
declare -A DOMAIN_KEY=()

cert_is_valid_30d() {
    local cert_file="$1"
    [[ -f "$cert_file" ]] && openssl x509 -in "$cert_file" -noout -checkend 2592000 >/dev/null 2>&1
}

for domain in "${DOMAINS[@]}"; do
    conf_path="${AVAILABLE_DIR}/${domain}"
    if [[ -L "$conf_path" ]]; then
        resolved=$(readlink -f "$conf_path" || true)
        [[ -n "$resolved" && -f "$resolved" ]] && conf_path="$resolved"
    fi

    cert_path=""
    key_path=""

    # 1. 优先尝试从现有 Nginx 站点配置读取证书路径
    if [[ -f "$conf_path" ]]; then
        cert_path=$(awk '$1 == "ssl_certificate" { v=$2; sub(/;$/, "", v); print v; exit }' "$conf_path" || true)
        key_path=$(awk '$1 == "ssl_certificate_key" { v=$2; sub(/;$/, "", v); print v; exit }' "$conf_path" || true)
        if [[ "$cert_path" == *'$'* || "$key_path" == *'$'* ]]; then
            cert_path=""
            key_path=""
        fi
    fi

    # 2. 尝试默认 Let's Encrypt 路径
    if [[ -z "$cert_path" || ! -f "$cert_path" ]]; then
        cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
        key_path="/etc/letsencrypt/live/${domain}/privkey.pem"
    fi

    if [[ -f "$cert_path" && -f "$key_path" ]] && cert_is_valid_30d "$cert_path"; then
        info "[${domain}] 检测到有效期 >30 天的现有证书，直接沿用：${cert_path}"
        DOMAIN_CERT[$domain]="$cert_path"
        DOMAIN_KEY[$domain]="$key_path"
    else
        info "[${domain}] 正在通过 Cloudflare DNS-01 申请 Let's Encrypt 证书 ..."
        certbot certonly \
            --dns-cloudflare \
            --dns-cloudflare-credentials "$CF_CRED_FILE" \
            --dns-cloudflare-propagation-seconds 20 \
            --non-interactive \
            --agree-tos \
            --register-unsafely-without-email \
            --keep-until-expiring \
            --cert-name "$domain" \
            -d "$domain"

        cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
        key_path="/etc/letsencrypt/live/${domain}/privkey.pem"

        if [[ ! -f "$cert_path" || ! -f "$key_path" ]]; then
            error "[${domain}] 证书签发后未找到证书文件：${cert_path}"
        fi
        info "[${domain}] 证书签发成功：${cert_path}"
        DOMAIN_CERT[$domain]="$cert_path"
        DOMAIN_KEY[$domain]="$key_path"
    fi
done

# 配置 Certbot 自动续期后重载 Nginx 的钩子
RENEW_HOOK="/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh"
mkdir -p "$(dirname "$RENEW_HOOK")"
cat > "$RENEW_HOOK" <<'EOF'
#!/usr/bin/env bash
systemctl reload nginx >/dev/null 2>&1 || true
EOF
chmod 755 "$RENEW_HOOK"

# ------------------------------------------------------------------------------
# 6. 生成逼真的网络测速伪装网页（HTTP 200 OK + 真实延迟/下行测速交互）
# ------------------------------------------------------------------------------
WEB_ROOT="/var/www/edge-speedtest"
mkdir -p "$WEB_ROOT"

# 生成 1 MiB 测速载荷文件供前端真实测速使用
if [[ ! -f "${WEB_ROOT}/chunk.bin" ]]; then
    dd if=/dev/urandom of="${WEB_ROOT}/chunk.bin" bs=64K count=16 status=none
    chmod 644 "${WEB_ROOT}/chunk.bin"
fi

cat > "${WEB_ROOT}/index.html" <<'HTML_EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Edge Network Quality & Speedtest Node</title>
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
    margin-bottom: 28px;
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
  .metric-value { font-size: 30px; font-weight: 700; margin: 8px 0 4px; font-variant-numeric: tabular-nums; }
  .metric-unit { font-size: 12px; color: var(--muted); }
  .progress-wrap {
    height: 8px;
    background: rgba(255, 255, 255, 0.06);
    border-radius: 999px;
    overflow: hidden;
    margin-bottom: 24px;
  }
  .progress-bar {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, #3b82f6, #06b6d4);
    transition: width 0.2s ease;
  }
  .actions { display: flex; justify-content: center; }
  button {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 12px;
    padding: 13px 36px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 8px 24px var(--accent-glow);
    transition: transform 0.15s ease, opacity 0.15s ease;
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
        <div class="metric-label">下行吞吐 (Download)</div>
        <div class="metric-value" id="dlVal">--</div>
        <div class="metric-unit">Mbps</div>
      </div>
    </div>

    <div class="progress-wrap"><div class="progress-bar" id="bar"></div></div>

    <div class="actions">
      <button id="startBtn" onclick="runTest()">开始网络测速</button>
    </div>

    <div class="footer">
      <span id="protoInfo">协议：TLS / HTTP</span>
      <span id="statusText">就绪 · 点击上方按钮发起边缘链路探测</span>
    </div>
  </div>

<script>
  document.getElementById('nodeHost').textContent = '接入节点：' + window.location.hostname;
  document.getElementById('protoInfo').textContent = '安全传输：' + window.location.protocol.replace(':', '').toUpperCase();

  async function runTest() {
    const btn = document.getElementById('startBtn');
    const bar = document.getElementById('bar');
    const status = document.getElementById('statusText');
    btn.disabled = true;
    bar.style.width = '5%';

    try {
      status.textContent = '正在测量边缘节点 RTT 延迟与抖动...';
      const samples = [];
      for (let i = 0; i < 6; i++) {
        const t0 = performance.now();
        await fetch('/api/ping?t=' + Date.now() + '_' + i, { cache: 'no-store' });
        const rtt = performance.now() - t0;
        if (i > 0) samples.push(rtt);
        bar.style.width = (10 + i * 7) + '%';
      }
      const avgPing = samples.reduce((a, b) => a + b, 0) / samples.length;
      let jitterSum = 0;
      for (let i = 1; i < samples.length; i++) jitterSum += Math.abs(samples[i] - samples[i - 1]);
      const jitter = samples.length > 1 ? jitterSum / (samples.length - 1) : 0;

      document.getElementById('pingVal').textContent = avgPing.toFixed(1);
      document.getElementById('jitterVal').textContent = jitter.toFixed(1);

      status.textContent = '正在执行多块下行吞吐基准测试...';
      let totalBytes = 0;
      const tStart = performance.now();
      const rounds = 6;
      for (let r = 0; r < rounds; r++) {
        const res = await fetch('/chunk.bin?r=' + Date.now() + '_' + r, { cache: 'no-store' });
        const buf = await res.arrayBuffer();
        totalBytes += buf.byteLength;
        const elapsedSec = (performance.now() - tStart) / 1000;
        const mbps = (totalBytes * 8) / (elapsedSec * 1000 * 1000);
        document.getElementById('dlVal').textContent = mbps.toFixed(1);
        bar.style.width = (52 + Math.round(((r + 1) / rounds) * 48)) + '%';
      }
      status.textContent = '测速完成 · 链路状态正常';
    } catch (e) {
      status.textContent = '测速中断：' + (e && e.message ? e.message : '网络异常');
    } finally {
      btn.disabled = false;
    }
  }
</script>
</body>
</html>
HTML_EOF
chmod 644 "${WEB_ROOT}/index.html"

# ------------------------------------------------------------------------------
# 7. 备份原有配置、写入新 Nginx 配置并支持全量原子回滚
# ------------------------------------------------------------------------------
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
declare -A BACKUP_MAP=()
declare -a NEW_CONFS=()
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
        if [[ -L "$conf" ]]; then
            conf=$(readlink -f "$conf")
        fi
        cp -a "$bak" "$conf"
        ln -sfn "$conf" "${ENABLED_DIR}/${domain}"
    done
    for domain in "${NEW_CONFS[@]:-}"; do
        [[ -z "$domain" ]] && continue
        rm -f "${ENABLED_DIR}/${domain}" "${AVAILABLE_DIR}/${domain}"
    done
    nginx -t >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true
}

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
            if [[ -z "$resolved" || ! -f "$resolved" ]]; then
                error "站点配置符号链接无效：$conf_path"
            fi
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

    return 301 https://\$host\$request_uri;
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

    location = /chunk.bin {
        default_type application/octet-stream;
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        try_files /chunk.bin =404;
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

# ------------------------------------------------------------------------------
# 8. 检测 Nginx 配置、重启服务并逐个域名验证 HTTPS 200 测速页
# ------------------------------------------------------------------------------
info "检测 Nginx 配置..."
if ! nginx -t; then
    rollback_all
    error "新配置检测失败，已恢复原配置"
fi

info "重启 Nginx 服务..."
systemctl enable nginx >/dev/null 2>&1 || true
if ! systemctl restart nginx; then
    rollback_all
    error "Nginx 重启失败，已恢复原配置"
fi

if ! ss -lnt | grep -qE ":${VERIFY_PORT}[[:space:]]"; then
    rollback_all
    error "Nginx 未监听 ${VERIFY_PORT} 端口，已恢复原配置"
fi

for domain in "${DOMAINS[@]}"; do
    # 1. 验证首页 200 OK 与测速站内容
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

    # 2. 验证 /api/ping 测速接口 200 OK
    PING_STATUS=$(curl -ksS -o /dev/null \
        --resolve "${domain}:${VERIFY_PORT}:127.0.0.1" \
        -w '%{http_code}' \
        "https://${domain}:${VERIFY_PORT}/api/ping" || true)

    if [[ "$PING_STATUS" != "200" ]]; then
        rollback_all
        error "[${domain}] 本机 /api/ping 验证状态码为 ${PING_STATUS}（预期 200），已恢复原配置"
    fi

    info "[${domain}] 本机 HTTPS 200 测速伪装页 & API 校验通过！"
done

echo
echo "============================================================"
echo -e "${GREEN}全部域名部署完成！${NC}"
echo
echo " 已部署域名 (${#DOMAINS[@]} 个)："
for domain in "${DOMAINS[@]}"; do
    echo "   - ${domain}  (证书: ${DOMAIN_CERT[$domain]})"
done
echo
echo " HTTPS 监听地址： ${LISTEN_SUMMARY}"
echo " HTTP 状态码：    200 OK（边缘节点网络质量测速伪装站）"
echo " 站点根目录：     ${WEB_ROOT}"
echo " CF 凭据路径：    ${CF_CRED_FILE} (权限 600，自动续期复用)"
if [[ "$LISTEN_MODE" == "1" ]]; then
    echo " 面板回落地址：   请在 RelayPanel 设备组将「SNI 兜底回落地址」设为 127.0.0.1:${INTERNAL_HTTPS_PORT}"
fi
echo "============================================================"
echo

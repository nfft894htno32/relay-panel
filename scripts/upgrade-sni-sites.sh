#!/usr/bin/env bash

set -Eeuo pipefail

# ==============================================================================
# 已部署节点免交互一键升级脚本（升级为方案 A：零刷流风险的轻量级延迟探测伪装页）
#
# 执行动作（全程免交互，3 秒完成，不断连、不改证书、不改 DNS）：
#   1. 物理删除 /var/www/edge-speedtest/chunk.bin 测速大文件
#   2. 将 /var/www/edge-speedtest/index.html 升级为方案 A（仅 <1KB 延迟/抖动探测 + 运维口令拦截压测）
#   3. 自动备份并清理 /etc/nginx/sites-available/* 中的 /chunk.bin location 块
#   4. 执行 nginx -t 校验并平滑 reload nginx，失败自动回滚
# ==============================================================================

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
NC="\033[0m"

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[×]${NC} $*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
    error "请使用 root 用户运行此升级脚本"
fi

WEB_ROOT="/var/www/edge-speedtest"
if [[ ! -d "$WEB_ROOT" ]]; then
    mkdir -p "$WEB_ROOT"
fi
chmod 755 /var /var/www "$WEB_ROOT"

# 1. 物理删除旧版 1MiB 测速文件
if [[ -f "${WEB_ROOT}/chunk.bin" ]]; then
    rm -f "${WEB_ROOT}/chunk.bin"
    info "已物理删除大体积测速载荷文件：${WEB_ROOT}/chunk.bin"
else
    info "未发现残留的 chunk.bin 文件，无需清理"
fi

# 2. 更新 index.html 为方案 A（仅开放 <1KB 真实 RTT 延迟探测 + 压测口令保护）
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
info "已更新零刷流风险伪装监测页：${WEB_ROOT}/index.html"

# 3. 清理 /etc/nginx/sites-available/* 中旧版的 `location = /chunk.bin { ... }` 块
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
declare -A BACKUP_CONFS=()
MODIFIED_COUNT=0

shopt -s nullglob
for conf in /etc/nginx/sites-available/*; do
    # 跳过历史备份文件本身
    [[ "$conf" == *.backup-* ]] && continue
    [[ ! -f "$conf" ]] && continue

    if grep -q 'location = /chunk\.bin' "$conf" 2>/dev/null; then
        bak="${conf}.backup-${TIMESTAMP}"
        cp -a "$conf" "$bak"
        BACKUP_CONFS[$conf]="$bak"

        tmp_f=$(mktemp "/tmp/nginx-upg.XXXXXX")
        awk '
            /^[[:space:]]*location = \/chunk\.bin[[:space:]]*\{/ { skip=1; next }
            skip && /^[[:space:]]*\}/ { skip=0; next }
            !skip { print }
        ' "$conf" > "$tmp_f"

        chmod --reference="$conf" "$tmp_f" 2>/dev/null || chmod 644 "$tmp_f"
        mv -f "$tmp_f" "$conf"
        MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
        info "已清理站点配置中的 /chunk.bin 接口：$(basename "$conf")"
    fi
done
shopt -u nullglob

rollback_confs() {
    warn "Nginx 配置检测未通过，正在自动回滚配置修改..."
    for conf in "${!BACKUP_CONFS[@]}"; do
        cp -a "${BACKUP_CONFS[$conf]}" "$conf"
    done
}

# 4. 校验并平滑热重载 Nginx（不断开现有连接）
if (( MODIFIED_COUNT > 0 )); then
    info "检测 Nginx 配置..."
    if ! nginx -t; then
        rollback_confs
        error "Nginx 配置检测失败，已恢复原站点配置"
    fi

    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
        info "Nginx 已平滑热重载 (reload)"
    else
        systemctl start nginx
        info "Nginx 已启动"
    fi
else
    info "Nginx 站点配置无需变动"
fi

echo
echo "============================================================"
echo -e "${GREEN}伪装测速页防刷升级完成！（方案 A）${NC}"
echo " - 大文件载荷： 已彻底移除 (/var/www/edge-speedtest/chunk.bin)"
echo " - 公开探测项： 仅保留 <1KB 的无损 RTT 延迟 / 抖动 / 可达率探测"
echo " - 压测防护：   吞吐压测已设为需运维授权拦截，0 刷流风险"
echo " - 转发影响：   0 影响（relay-node 四层转发与本地 Nginx 完全解耦）"
echo "============================================================"
echo

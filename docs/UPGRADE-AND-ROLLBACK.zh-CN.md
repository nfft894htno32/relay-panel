# RelayPanel 生产环境平滑升级与一键回滚指南

本文档针对当前运行 **官方最新生产版本（v1.2.20 / node-v1.2.11）** 的环境，提供零数据丢失的**平滑升级流程**与**秒级回滚方案**。

---

## 一、 数据库兼容性与安全保障说明

在 [`crates/panel/src/db/schema.rs`](file:///C:/Users/Administrator/Desktop/relaynode改进/relay-panel/crates/panel/src/db/schema.rs) 与 [`crates/panel/src/db/pg_schema.rs`](file:///C:/Users/Administrator/Desktop/relaynode改进/relay-panel/crates/panel/src/db/pg_schema.rs) 中，我们已经做了**非破坏性（Non-Destructive）前向/后向兼容设计**，并通过了专门针对官方 `v1.2.20` 生产库结构的自动迁移单元测试（[`official_v1_2_20_production_db_upgrades_cleanly_with_foreign_keys_on`](file:///C:/Users/Administrator/Desktop/relaynode改进/relay-panel/crates/panel/src/db/schema.rs#L204-L359)）：

1. **绝不删除旧表（保留外键完整性与回滚能力）**：
   - 升级迁移不会 `DROP` 原库中的 `plans`、`tunnel_profiles`、`orders`、`redeem_codes`、`app_settings` 等旧表。
   - 这既避免了旧库 `users` / `forward_rules` 表定义中残留的 `REFERENCES plans(id)` / `REFERENCES tunnel_profiles(id)` 在 `PRAGMA foreign_keys = ON` 下报错，又保证了所有历史数据原封不动。
2. **自动增量补齐新字段**：
   - 自动在 `device_groups` 表新增 `sni_fallback_addr`（默认 `'127.0.0.1:10443'`）和 `sni_loop_bypass_ips`（默认 `''`）。
   - 自动在 `forward_rules` 表新增 `sni` 字段（已有规则均为 `NULL`，行为与升级前 100% 一致，按原有裸 TCP/UDP 模式转发）。
   - 自动将单端口唯一索引 `idx_fr_port_tcp` 升级为部分唯一索引 `idx_fr_port_tcp_raw` 与 `idx_fr_port_tcp_sni`。
3. **协议向前/向后兼容**：
   - 新增的协议字段（`sni`、`sni_fallback_addr`、`sni_loop_bypass_ips`）全部带有 `#[serde(default)]`。
   - **升级顺序自由**：先升级面板（Panel）时，尚未升级的旧版节点（`relay-node`）拉取配置会自动忽略新字段，原有规则继续正常转发零中断；随后逐台替换节点二进制即可开启单 443 端口多 SNI 分流能力。

---

## 二、 升级前：10 秒完成生产快照备份（必做）

登录您的 **面板服务器**，进入官方原版 `relay-panel` 部署目录（假设为 `/opt/relay-panel` 或 `~/relay-panel`）：

```bash
cd /opt/relay-panel   # 请替换为您实际的部署目录

# 1. 创建备份目录
BACKUP_DIR="/root/relaypanel-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# 2. 备份配置文件 (.env / Caddyfile / docker-compose)
cp -a .env "$BACKUP_DIR/" 2>/dev/null || true
cp -a Caddyfile "$BACKUP_DIR/" 2>/dev/null || true

# 3. 在线热备份数据库
# 【情况 A：默认 SQLite 数据库】使用项目自带的在线热备脚本（支持 WAL 安全快照）
bash scripts/sqlite-backup.sh "$BACKUP_DIR/data.db"

# 【情况 B：如果您使用的是 PostgreSQL】
# docker compose exec -T postgres pg_dump -U relaypanel -Fc relaypanel > "$BACKUP_DIR/pg_dump.custom"

# 4. 为当前正在运行的官方容器镜像打上 rollback 标签
PANEL_IMAGE=$(docker compose ps --format '{{.Image}}' panel)
docker tag "$PANEL_IMAGE" relaypanel-rollback/panel:official
echo "$PANEL_IMAGE" > "$BACKUP_DIR/official_panel_image.txt"

echo "✅ 备份已完成，保存在: $BACKUP_DIR"
ls -lh "$BACKUP_DIR"
```

---

## 三、 平滑升级步骤（转发业务零中断）

### 第一步：升级面板端（Panel）

将改造后的 [`relay-panel`](file:///C:/Users/Administrator/Desktop/relaynode改进/relay-panel) 代码上传或同步到面板服务器（例如放在 `/opt/relay-panel-custom`，或者直接覆盖原代码目录但保留原有的 `.env` 文件）：

```bash
# 假设把改造后的代码放在 /opt/relay-panel-custom，并复用原目录的 .env
cp -a /opt/relay-panel/.env /opt/relay-panel-custom/.env
cd /opt/relay-panel-custom

# 使用本地源码构建模式启动（会自动复用原有的 Docker Volume `panel_data`）
# 注意：通过 -p 指定与原目录相同的 Compose 项目名（默认为原目录名，可通过 `docker compose ls` 查看）
RELAYPANEL_BUILD_LOCAL=1 ./deploy.sh
```

> **提示**：如果您是直接在原 `/opt/relay-panel` 目录替换了源码文件（保留了 `.env`），只需直接在原目录执行：
> ```bash
> cd /opt/relay-panel
> RELAYPANEL_BUILD_LOCAL=1 ./deploy.sh
> ```
> 脚本会自动编译新版前后端镜像、重启 `panel` 容器并验证 `GET /api/v1/health` 正常返回。此时所有已有节点和已有转发规则**不会中断**。

---

### 第二步：升级转发节点（Node）

面板升级完成后，您可以利用 Docker 编译出与目标系统（Debian/Ubuntu `glibc`）兼容的 `relay-node` 二进制文件，平滑替换各台转发机上的 `/opt/relay-node/relay-node`。

#### 1. 在面板机上导出编译好的 `relay-node` 二进制文件

```bash
cd /opt/relay-panel-custom   # 或 /opt/relay-panel

# 构建 node 镜像并导出二进制文件
docker build --target node -t relaypanel-custom/node:latest .
docker create --name tmp-relay-node relaypanel-custom/node:latest
docker cp tmp-relay-node:/app/relay-node ./relay-node-linux-amd64
docker rm tmp-relay-node
chmod +x ./relay-node-linux-amd64
```

#### 2. 在每台转发节点（Node 服务器）上备份并原子替换

将 `./relay-node-linux-amd64` 通过 `scp` 上传到您的转发节点服务器 `/tmp/relay-node.new`，然后在转发节点上执行：

```bash
# 1. 备份官方原版二进制（供一键回滚使用）
cp -a /opt/relay-node/relay-node /opt/relay-node/relay-node.official.bak

# 2. 原子替换二进制文件（Linux 下 mv 可直接替换正在运行的二进制，不会报 Text file busy）
chmod +x /tmp/relay-node.new
mv -f /tmp/relay-node.new /opt/relay-node/relay-node

# 3. 重启服务（支持优雅 Drain）
systemctl restart relay-node

# 4. 检查状态与日志
systemctl status relay-node --no-pager
journalctl -u relay-node -n 20 --no-pager
```

#### 3. （可选）在启用单 443 端口多 SNI 的转发机上部署 10443 兜底站点

如果您要在该节点开启 443 端口多 SNI 分流并配合本地 `127.0.0.1:10443` 403 站点防回环兜底：
- 如果之前这台机器用外部 Nginx `stream` 占用了 443 端口，请先注释掉外部 Nginx 的 `stream { ... 443 ... }` 块并 `nginx -s reload`，让出 443 端口给 `relay-node`。
- 运行我们为您准备好的 [`bind_403_site.sh`](file:///C:/Users/Administrator/Desktop/relaynode改进/bind_403_site.sh)，让本地 Nginx 在 `127.0.0.1:10443` 监听并返回 403。

---

## 四、 一键回滚方案（随时秒级切回官方原版）

万一您在任何时候希望切回官方最新原版，只需按以下两步执行，**耗时不超过 15 秒**：

### 1. 回滚转发节点（Node 服务器）

在转发节点服务器上执行：

```bash
# 还原备份的官方原版二进制并重启
cp -f /opt/relay-node/relay-node.official.bak /opt/relay-node/relay-node
systemctl restart relay-node
```

### 2. 回滚面板端（Panel 服务器）

在面板服务器上，您有两种回滚方式可选：

#### 方式 A：完整还原到升级前的数据库备份 + 官方镜像（最彻底）

```bash
cd /opt/relay-panel
BACKUP_DIR="/root/relaypanel-backup-XXXXXX"   # 替换为您升级前生成的备份目录

# 1. 停止当前面板容器
docker compose stop panel

# 2. 将备份的 data.db 拷回容器数据卷，并清理 shm/wal 临时文件
VOLUME_PATH=$(docker volume inspect --format '{{.Mountpoint}}' "$(docker compose config --volumes | head -n1)" 2>/dev/null || docker inspect --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}' "$(docker compose ps -q panel)")
rm -f "${VOLUME_PATH}/data.db-wal" "${VOLUME_PATH}/data.db-shm"
cp -f "$BACKUP_DIR/data.db" "${VOLUME_PATH}/data.db"
chown 10001:10001 "${VOLUME_PATH}/data.db"

# 3. 使用官方发布版 compose 启动原版镜像
docker compose -f docker-compose.release.yaml up -d
```

#### 方式 B：保留升级期间产生的流量统计数据，直接切回官方原版镜像（热降级）

因为我们在升级时**没有删除任何旧表**，如果您还没有在同一个端口创建多条重复端口的 SNI 规则（或者先在面板删掉同端口多余的 SNI 规则），甚至不需要还原旧数据库备份，只需直接启动官方镜像即可：

```bash
cd /opt/relay-panel
docker compose -f docker-compose.release.yaml up -d
```
官方原版镜像启动时会自动执行 `CREATE UNIQUE INDEX IF NOT EXISTS idx_fr_port_tcp ...`，并直接读取现有的全部设备组、规则和流量统计数据！

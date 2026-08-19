#!/usr/bin/env bash
# SFSS 蓝区(数据交换区)一键部署脚本 —— 在蓝区虚拟机上以 root 运行
#
# 用法:
#   ./blue-deploy.sh pilot       # 试点模式:development 环境,先跑通业务流程
#   ./blue-deploy.sh production  # 生产模式:完整 mTLS/指纹/预检门禁(证书与 env 需先就位)
#
# 前置(见 deploy/CERTS.md 证书清单):
#   /etc/sfss/tls/    证书(生产必需;试点可空)
#   /etc/sfss/sfss-{inbound,outbound}.env  本脚本生成骨架,补齐 REPLACE 项后重启服务
# 产物:
#   /opt/sfss/venv、/srv/sfss-{inbound,outbound}、systemd 两单元、
#   /etc/nginx/sfss/{blue-core.conf,edge.conf,admin.conf}
set -euo pipefail

MODE="${1:-}"
[[ "$MODE" == "pilot" || "$MODE" == "production" ]] || { echo "用法: $0 {pilot|production}"; exit 1; }
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SFSS_USER=sfss
SFSS_HOME=/opt/sfss
DATA_IN=/srv/sfss-inbound
DATA_OUT=/srv/sfss-outbound
TLS_DIR=/etc/sfss/tls

log() { echo "[blue-deploy] $*"; }
die() { echo "[blue-deploy] 错误: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请以 root 运行"
command -v nginx >/dev/null || die "未安装 nginx"
command -v python3 >/dev/null || die "未安装 python3"

# ---------------------------------------------------------------- 1. 账号与目录
if ! id "$SFSS_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$SFSS_HOME" --shell /usr/sbin/nologin "$SFSS_USER"
  log "已创建系统账号 $SFSS_USER"
fi
mkdir -p "$SFSS_HOME" "$DATA_IN" "$DATA_OUT" "$TLS_DIR" /etc/sfss/rules /etc/sfss/secrets
chown "$SFSS_USER:$SFSS_USER" "$DATA_IN" "$DATA_OUT"
chmod 0700 "$DATA_IN" "$DATA_OUT"

# ---------------------------------------------------------------- 2. Python 环境
if [[ ! -x "$SFSS_HOME/venv/bin/python" ]]; then
  log "创建 venv…"
  python3 -m venv "$SFSS_HOME/venv"
  "$SFSS_HOME/venv/bin/pip" install --upgrade pip -q
fi
if ! "$SFSS_HOME/venv/bin/python" -c "import sfss" 2>/dev/null; then
  log "安装 sfss + 依赖…"
  if compgen -G "$REPO_DIR/dist/sfss-*.whl" >/dev/null; then
    "$SFSS_HOME/venv/bin/pip" install -q --no-deps "$REPO_DIR"/dist/sfss-*.whl
  else
    "$SFSS_HOME/venv/bin/pip" install -q "$REPO_DIR"
  fi
  "$SFSS_HOME/venv/bin/pip" install -q ldap3==2.9.1 pyasn1==0.6.4
fi
chown -R "$SFSS_USER:$SFSS_USER" "$SFSS_HOME"
log "Python 环境就绪"

# ---------------------------------------------------------------- 3. 环境文件骨架
gen_env() {
  local sys=$1 file="/etc/sfss/sfss-$1.env" data_dir
  [[ "$sys" == "inbound" ]] && data_dir="$DATA_IN" || data_dir="$DATA_OUT"
  if [[ -f "$file" ]]; then log "$file 已存在,保留"; return; fi
  local env_value="development"; [[ "$MODE" == "production" ]] && env_value="production"
  local proxy="false";           [[ "$MODE" == "production" ]] && proxy="true"
  {
    echo "# SFSS $sys —— blue-deploy.sh 生成的骨架,补齐 REPLACE 项后 systemctl restart sfss-$sys"
    echo "SFSS_ENVIRONMENT=$env_value"
    echo "SFSS_DEPLOYMENT_MODE=$sys"
    echo "SFSS_DATA_DIR=$data_dir"
    echo "SFSS_AUTH_BACKEND=ldap"
    echo "SFSS_LDAP_URI=ldaps://REPLACE_LDAP_HOST:636"
    echo "SFSS_LDAP_BASE_DN=REPLACE_BASE_DN"
    echo "SFSS_LDAP_USER_TEMPLATE=uid={username},ou=People,{base_dn}"
    echo "SFSS_BOOTSTRAP_ADMINS=REPLACE_LDAP_ADMIN"
    echo "SFSS_LDAP_FALLBACK_ADMIN=admin"
    echo "SFSS_DEV_TOKENS_ENABLED=false"
    echo "SFSS_LOCAL_CREDENTIALS="
    echo "SFSS_SCANNERS=clamav"
    echo "SFSS_CLAMAV_HOST=127.0.0.1"
    echo "SFSS_CLAMAV_PORT=3310"
    echo "SFSS_CLAMAV_STREAM_MAX_BYTES=2147483648"
    echo "SFSS_TRUSTED_ZONE_PROXY_CIDRS=127.0.0.1/32,::1/128"
    echo "SFSS_ADMIN_SOURCE_CIDRS=REPLACE_ADMIN_CIDR"
    echo "SFSS_REQUIRE_TRUSTED_PROXY=$proxy"
    echo "SFSS_REQUIRE_FORWARDED_HTTPS=$proxy"
    echo "SFSS_MAX_UPLOAD_BYTES=2147483648"
    echo "SFSS_MIN_FREE_BYTES=107374182400"
    echo "SFSS_SESSION_TTL_SECONDS=3600"
    echo "SFSS_SESSION_IDLE_SECONDS=900"
    echo "SFSS_MAX_SESSIONS_PER_USER=3"
    echo "SFSS_SERVICE_TOKEN_MAX_TTL_SECONDS=2592000"
  } > "$file"
  if [[ "$MODE" == "production" ]]; then
    {
      echo "SFSS_RELEASE_ID=REPLACE_WITH_SIGNED_RELEASE_ID"
      echo "SFSS_EXPECTED_PYTHON_VERSION=REPLACE_MAJOR_MINOR_PATCH"
      echo "SFSS_EXPECTED_CONFIG_SHA256=REPLACE_64_HEX_DIGEST"
      echo "SFSS_MANIFEST_HMAC_KEY_FILE=/etc/sfss/secrets/manifest-hmac"
    } >> "$file"
    [[ "$sys" == "outbound" ]] && echo "SFSS_ALLOW_LOCAL_APPROVAL=false" >> "$file"
  fi
  chmod 0600 "$file"
  log "已生成 $file(补齐 REPLACE 项)"
}
gen_env inbound
gen_env outbound

# ---------------------------------------------------------------- 4. systemd
install_unit() {
  sed -e "s#EnvironmentFile=.*#EnvironmentFile=/etc/sfss/sfss-$1.env#" \
      -e "s#^ReadWritePaths=.*#ReadWritePaths=$( [[ $1 == inbound ]] && echo $DATA_IN || echo $DATA_OUT )#" \
      "$REPO_DIR/deploy/systemd/sfss-$1.service" > "/etc/systemd/system/sfss-$1.service"
}
install_unit inbound
install_unit outbound
systemctl daemon-reload
log "systemd 单元已安装(sfss-inbound / sfss-outbound)"

# ---------------------------------------------------------------- 5. nginx
mkdir -p /etc/nginx/sfss

# 5a. 蓝核:生产 = 8443 mTLS SNI 分流;试点 = 仅 upstream
if [[ "$MODE" == "production" ]]; then
  for f in blue-fullchain.pem blue-key.pem zone-gateway-ca.pem zone-gateway-ca.crl.pem; do
    [[ -f "$TLS_DIR/$f" ]] || die "生产模式缺少 $TLS_DIR/$f(见 deploy/CERTS.md)"
  done
  # 合并两套 blue-core 为一个配置:共享 map/zone 定义只保留一份
  awk '
    !seen_map && /^map /  { seen_map=1 }
    !seen_zone && /^limit_req_zone|limit_conn_zone/ { seen_zone=1 }
    /limit_req_zone|limit_conn_zone/ && seen_zone { next }
    { print }
  ' "$REPO_DIR/deploy/nginx/blue-core-inbound.conf" > /etc/nginx/sfss/blue-core.conf.tmp
  # 去掉第二份文件中重复的全局指令,只追加 server 块
  awk '/^server \{/,0' "$REPO_DIR/deploy/nginx/blue-core-outbound.conf" >> /etc/nginx/sfss/blue-core.conf.tmp
  # 补充第二 server 缺少的限流引用(直接复用同 zone)
  mv /etc/nginx/sfss/blue-core.conf.tmp /etc/nginx/sfss/blue-core.conf
  log "已生成 blue-core.conf(生产 8443 mTLS,SNI: blue-in-sfss.internal / blue-out-sfss.internal)"
else
  cat > /etc/nginx/sfss/blue-core.conf <<'EOF'
# 试点模式:SFSS 只监听 Unix socket,由 edge.conf 统一终结 TLS 后转发
upstream sfss_inbound_core  { server unix:/run/sfss-inbound/sfss.sock;  keepalive 64; }
upstream sfss_outbound_core { server unix:/run/sfss-outbound/sfss.sock; keepalive 64; }
EOF
  log "已生成试点版 blue-core.conf(仅 upstream)"
fi

# 5b. 边缘入口:443 SNI 分流 green/red(试点即对外;生产时绿红网关已直连 8443,此块仍可留作直连调试)
if [[ "$MODE" == "pilot" ]] || [[ -f "$TLS_DIR/edge-fullchain.pem" ]]; then
  cat > /etc/nginx/sfss/edge.conf <<EOF
# 对外边缘(443):green-*/red-* 按域名分流;蓝区应用通过 X-SFSS-* 头识别区域
limit_req_zone \$binary_remote_addr zone=sfss_edge_api:10m rate=20r/s;
limit_req_zone \$binary_remote_addr zone=sfss_edge_login:10m rate=5r/m;
limit_conn_zone \$binary_remote_addr zone=sfss_edge_conn:10m;

# ---- 入站系统(绿区上传) ----
server {
    listen 443 ssl;
    server_name green-in.REPLACE_DOMAIN;
    ssl_certificate     ${TLS_DIR}/green-in-fullchain.pem;
    ssl_certificate_key ${TLS_DIR}/green-in-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off; server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 140m; proxy_request_buffering off; proxy_buffering off;
    proxy_read_timeout 3600s; proxy_send_timeout 3600s;
    proxy_set_header X-SFSS-Zone PLACEHOLDER_ZONE;
    location = /v1/auth/login { limit_except POST { deny all; } limit_req zone=sfss_edge_login burst=5 nodelay; proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/(green|app\\.js|styles\\.css|favicon\\.ico|health)$ { limit_except GET { deny all; } proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/(me|objects)$ { limit_except GET { deny all; } proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/uploads { proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/objects { limit_except GET { deny all; } proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location / { return 404; }
}
server {
    listen 443 ssl;
    server_name red-in.REPLACE_DOMAIN;
    ssl_certificate     ${TLS_DIR}/red-in-fullchain.pem;
    ssl_certificate_key ${TLS_DIR}/red-in-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off; server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 140m; proxy_request_buffering off; proxy_buffering off;
    proxy_read_timeout 3600s; proxy_send_timeout 3600s;
    location = /v1/auth/login { limit_except POST { deny all; } limit_req zone=sfss_edge_login burst=5 nodelay; proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/(red|app\\.js|styles\\.css|favicon\\.ico|health)$ { limit_except GET { deny all; } proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/(me|objects)$ { limit_except GET { deny all; } proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/objects/[^/]+/download$ { limit_except GET { deny all; } proxy_pass http://sfss_inbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location / { return 404; }
}

# ---- 外发系统(红区上传->审批->绿区下载) ----
server {
    listen 443 ssl;
    server_name red-out.REPLACE_DOMAIN;
    ssl_certificate     ${TLS_DIR}/red-out-fullchain.pem;
    ssl_certificate_key ${TLS_DIR}/red-out-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off; server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 140m; proxy_request_buffering off; proxy_buffering off;
    proxy_read_timeout 3600s; proxy_send_timeout 3600s;
    location = /v1/auth/login { limit_except POST { deny all; } limit_req zone=sfss_edge_login burst=5 nodelay; proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/(red|app\\.js|styles\\.css|favicon\\.ico|health)$ { limit_except GET { deny all; } proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/(me|outbound)$ { limit_except GET { deny all; } proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/uploads { proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/outbound/[^/]+$ { limit_except GET { deny all; } proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location / { return 404; }
}
server {
    listen 443 ssl;
    server_name green-out.REPLACE_DOMAIN;
    ssl_certificate     ${TLS_DIR}/green-out-fullchain.pem;
    ssl_certificate_key ${TLS_DIR}/green-out-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off; server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 140m; proxy_request_buffering off; proxy_buffering off;
    proxy_read_timeout 3600s; proxy_send_timeout 3600s;
    location = /v1/auth/login { limit_except POST { deny all; } limit_req zone=sfss_edge_login burst=5 nodelay; proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/(green|app\\.js|styles\\.css|favicon\\.ico|health)$ { limit_except GET { deny all; } proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/(me|outbound)$ { limit_except GET { deny all; } proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location ~ ^/v1/outbound/[^/]+/download$ { limit_except GET { deny all; } proxy_pass http://sfss_outbound_core; include /etc/nginx/sfss/edge-common.inc; }
    location / { return 404; }
}
EOF
  cat > /etc/nginx/sfss/edge-common.inc <<'EOF'
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header Connection "";
EOF
  # 区域头:edge.conf 的四个 server 分别写死
  for entry in "green-in:green:inbound" "red-in:red:inbound" "red-out:red:outbound" "green-out:green:outbound"; do
    host=${entry%%:*}; rest=${entry#*:}; zone=${rest%%:*}
    grep -q "X-SFSS-Zone" /etc/nginx/sfss/edge-common.inc && break
  done
  # 逐 server 追加区域头(在 include 行后插入 proxy_set_header)
  python3 - <<'PY' 2>/dev/null || true
import re, pathlib
p = pathlib.Path("/etc/nginx/sfss/edge.conf")
c = p.read_text()
zones = {"green-in":"green","red-in":"red","red-out":"red","green-out":"green"}
for host, zone in zones.items():
    c = re.sub(
        rf'(server_name {host}\.REPLACE_DOMAIN;.*?)(location)',
        rf'\1    proxy_set_header X-SFSS-Zone {zone};\n    \2',
        c, count=1, flags=re.S)
p.write_text(c)
PY
  # 每个 server 块写死自己的 zone 头
  python3 - <<'PYZONE'
import re, pathlib
p = pathlib.Path("/etc/nginx/sfss/edge.conf")
c = p.read_text()
zones = {"green-in": "green", "red-in": "red", "red-out": "red", "green-out": "green"}
blocks = c.split("\nserver {")
out = [blocks[0]]
for block in blocks[1:]:
    for host, zone in zones.items():
        if f"server_name {host}." in block:
            block = block.replace("PLACEHOLDER_ZONE", zone)
            break
    out.append(block)
p.write_text("\nserver {".join(out).replace("PLACEHOLDER_ZONE", "green"))
PYZONE
  log "已生成 edge.conf(443 SNI: green-in / red-in / red-out / green-out,含 zone 头)"
fi

# 5c. 管理面(独立监听,仅管理网)
cat > /etc/nginx/sfss/admin.conf <<EOF
upstream sfss_in_admin  { server unix:/run/sfss-inbound/sfss.sock; }
upstream sfss_out_admin { server unix:/run/sfss-outbound/sfss.sock; }
limit_req_zone \$binary_remote_addr zone=sfss_admin_api:10m rate=10r/s;
server {
    listen 8443-admin sf;  # 占位注释:实际端口见下方 server
}
EOF
# 上面占位写法非法,直接重写干净版本
cat > /etc/nginx/sfss/admin.conf <<EOF
upstream sfss_in_admin  { server unix:/run/sfss-inbound/sfss.sock; }
upstream sfss_out_admin { server unix:/run/sfss-outbound/sfss.sock; }
server {
    listen 127.0.0.1:9443 ssl;
    server_name admin-in.sfss.internal;
$( [[ "$MODE" == "production" ]] && echo "    ssl_certificate     $TLS_DIR/blue-fullchain.pem;
    ssl_certificate_key $TLS_DIR/blue-key.pem;" || echo "    # 试点模式:自签证书占位(如无证书将导致此 server 无法启动,可整段注释)")
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off; server_tokens off;
    location / { proxy_pass http://sfss_in_admin; include /etc/nginx/sfss/admin-proxy.inc; }
}
server {
    listen 127.0.0.1:9444 ssl;
    server_name admin-out.sfss.internal;
$( [[ "$MODE" == "production" ]] && echo "    ssl_certificate     $TLS_DIR/blue-fullchain.pem;
    ssl_certificate_key $TLS_DIR/blue-key.pem;" || echo "    # 试点模式:自签证书占位")
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off; server_tokens off;
    location / { proxy_pass http://sfss_out_admin; include /etc/nginx/sfss/admin-proxy.inc; }
}
EOF
cat > /etc/nginx/sfss/admin-proxy.inc <<'EOF'
proxy_http_version 1.1;
proxy_set_header X-SFSS-Gateway-Role admin;
proxy_set_header X-SFSS-Zone "";
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header Connection "";
EOF

if ! grep -q "include /etc/nginx/sfss" /etc/nginx/nginx.conf; then
  sed -i '0,/^http {/s//http {\n    include \/etc\/nginx\/sfss\/*.conf;/' /etc/nginx/nginx.conf
fi
if nginx -t 2>/dev/null; then
  nginx -s reload 2>/dev/null || true
  log "nginx 已 reload"
else
  log "警告: nginx -t 未通过,请检查 /etc/nginx/sfss/(试点模式无证书时先注释 admin.conf 两个 server)"
fi

# ---------------------------------------------------------------- 6. 收尾提示
if ! command -v clamdscan >/dev/null && ! ss -ltn 2>/dev/null | grep -q :3310; then
  log "提示:未检测到 clamd。启用真实扫描需安装 ClamAV 并监听 127.0.0.1:3310"
fi

if [[ "$MODE" == "production" ]]; then
  cat <<'EOF'

[blue-deploy] 生产模式后续步骤:
  1. 补齐 /etc/sfss/sfss-{inbound,outbound}.env 中所有 REPLACE 项
  2. 放置证书到 /etc/sfss/tls/(清单见 deploy/CERTS.md)
  3. 逐系统执行:
       set -a; . /etc/sfss/sfss-inbound.env; set +a
       /opt/sfss/venv/bin/sfss-admin initialize      --data-dir /srv/sfss-inbound
       /opt/sfss/venv/bin/sfss-admin config-fingerprint --data-dir /srv/sfss-inbound
       # 把输出的 SHA-256 写回 env 的 SFSS_EXPECTED_CONFIG_SHA256,再:
       /opt/sfss/venv/bin/sfss-admin preflight
  4. systemctl enable --now sfss-inbound sfss-outbound
EOF
else
  systemctl enable --now sfss-inbound sfss-outbound || log "提示:请补齐 env 后手动 systemctl start sfss-inbound sfss-outbound"
  sleep 2
  systemctl --no-pager -l status sfss-inbound sfss-outbound 2>/dev/null | head -14 || true
  cat <<'EOF'

[blue-deploy] 试点模式:补齐 env 的 LDAP/admin CIDR 后 restart 两服务即可。
管理面(本机调试): 127.0.0.1:9443(inbound)/9444(outbound)。
EOF
fi
log "完成。证书放置说明: deploy/CERTS.md"

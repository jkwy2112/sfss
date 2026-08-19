#!/usr/bin/env bash
# SFSS 绿区/红区网关安装脚本 —— 在对应的绿区或红区虚拟机上以 root 运行
#
# 用法:
#   ./gateway-install.sh green <蓝区IP> [inbound|outbound]
#   ./gateway-install.sh red   <蓝区IP> [inbound|outbound]
#
# 示例(绿区VM,同时充当入站上传和外发下载入口):
#   ./gateway-install.sh green 10.1.20.5 inbound
#   ./gateway-install.sh green 10.1.20.5 outbound    # 可再装一套(不同域名/端口)
#
# 前置(见 deploy/CERTS.md):
#   /etc/sfss/tls/ 下放好本网关证书 + 蓝区 CA(生产还需 CRL + mTLS 客户端证书)
# 产物:
#   /etc/nginx/sfss/gateway-<zone>-<sys>.conf  443 对外,转发蓝区 8443
set -euo pipefail

ZONE="${1:-}"      # green | red
BLUE_IP="${2:-}"   # 蓝区虚拟机地址
SYS="${3:-inbound}" # inbound | outbound

usage() { echo "用法: $0 {green|red} <蓝区IP> [inbound|outbound]"; exit 1; }
[[ "$ZONE" == "green" || "$ZONE" == "red" ]] || usage
[[ -n "$BLUE_IP" ]] || usage
[[ "$SYS" == "inbound" || "$SYS" == "outbound" ]] || usage
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { echo "[gateway-install] $*"; }
die() { echo "[gateway-install] 错误: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请以 root 运行"
command -v nginx >/dev/null || die "未安装 nginx"

TLS_DIR=/etc/sfss/tls
NGINX_SFSS=/etc/nginx/sfss
mkdir -p "$TLS_DIR" "$NGINX_SFSS"

# 网关证书命名(与 CERTS.md 一致):<zone>-<sys>-fullchain.pem / -key.pem
GW_CERT="$TLS_DIR/${ZONE}-${SYS}-fullchain.pem"
GW_KEY="$TLS_DIR/${ZONE}-${SYS}-key.pem"
BLUE_CA="$TLS_DIR/blue-ca.pem"
BLUE_CRL="$TLS_DIR/blue-ca.crl.pem"
CLIENT_CERT="$TLS_DIR/${ZONE}-gateway-client.pem"
CLIENT_KEY="$TLS_DIR/${ZONE}-gateway-client-key.pem"

if [[ ! -f "$GW_CERT" || ! -f "$GW_KEY" ]]; then
  die "缺少网关证书 $GW_CERT / $GW_KEY(清单见 deploy/CERTS.md)"
fi
if [[ ! -f "$BLUE_CA" ]]; then
  log "警告: 无 $BLUE_CA,将不校验蓝区证书(仅试点;生产必须放置)"
fi

# 生产 = 具备 mTLS 客户端证书;否则试点(只验证服务端)
MTLS_BLOCK=""
if [[ -f "$CLIENT_CERT" && -f "$CLIENT_KEY" ]]; then
  MTLS_BLOCK="    proxy_ssl_certificate $CLIENT_CERT;
    proxy_ssl_certificate_key $CLIENT_KEY;"
  log "启用网关→蓝区 mTLS(客户端证书 CN 需为 sfss-${ZONE}-gateway)"
fi
PROXY_SSL_VERIFY="off"; VERIFY_DEPTH=""
if [[ -f "$BLUE_CA" ]]; then
  PROXY_SSL_VERIFY="on"
  VERIFY_DEPTH="    proxy_ssl_verify_depth 2;"
  [[ -f "$BLUE_CRL" ]] && VERIFY_DEPTH="$VERIFY_DEPTH
    proxy_ssl_crl $BLUE_CRL;"
fi

BLUE_HOST="blue-$([[ "$SYS" == "inbound" ]] && echo in || echo out)-sfss.internal"
CONF="$NGINX_SFSS/gateway-$ZONE-$SYS.conf"
DOMAIN="${ZONE}-$([[ "$SYS" == "inbound" ]] && echo in || echo out).REPLACE_DOMAIN"

ZONE_HEADER=$([[ "$ZONE" == "green" ]] && echo "绿区" || echo "红区")
if [[ "$SYS" == "inbound" ]]; then
  if [[ "$ZONE" == "green" ]]; then
    ROUTES='    location = /v1/auth/login { limit_except POST { deny all; } limit_req zone=sfss_login burst=5 nodelay; include $UPSTREAM_INC; }
    location = /v1/auth/logout { limit_except POST { deny all; } include $UPSTREAM_INC; }
    location ~ ^/(green|app\.js|styles\.css|favicon\.ico|health)$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location ~ ^/v1/(me|objects)$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location ~ ^/v1/uploads { proxy_pass_request_headers on; include $UPSTREAM_INC; }
    location ~ ^/v1/objects/[^/]+$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location / { return 404; }'
    EXTRA_NOTE="绿区入站上传"
  else
    ROUTES='    location = /v1/auth/login { limit_except POST { deny all; } limit_req zone=sfss_login burst=5 nodelay; include $UPSTREAM_INC; }
    location = /v1/auth/logout { limit_except POST { deny all; } include $UPSTREAM_INC; }
    location ~ ^/(red|app\.js|styles\.css|favicon\.ico|health)$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location ~ ^/v1/(me|objects)$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location ~ ^/v1/objects/[^/]+/download$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location / { return 404; }'
    EXTRA_NOTE="红区入站下载(本人文件)"
  fi
else
  if [[ "$ZONE" == "red" ]]; then
    ROUTES='    location = /v1/auth/login { limit_except POST { deny all; } limit_req zone=sfss_login burst=5 nodelay; include $UPSTREAM_INC; }
    location = /v1/auth/logout { limit_except POST { deny all; } include $UPSTREAM_INC; }
    location ~ ^/(red|app\.js|styles\.css|favicon\.ico|health)$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location ~ ^/v1/(me|outbound)$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location ~ ^/v1/uploads { include $UPSTREAM_INC; }
    location ~ ^/v1/outbound/[^/]+$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location / { return 404; }'
    EXTRA_NOTE="红区外发上传"
  else
    ROUTES='    location = /v1/auth/login { limit_except POST { deny all; } limit_req zone=sfss_login burst=5 nodelay; include $UPSTREAM_INC; }
    location = /v1/auth/logout { limit_except POST { deny all; } include $UPSTREAM_INC; }
    location ~ ^/(green|app\.js|styles\.css|favicon\.ico|health)$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location ~ ^/v1/(me|outbound)$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location ~ ^/v1/outbound/[^/]+/download$ { limit_except GET { deny all; } include $UPSTREAM_INC; }
    location / { return 404; }'
    EXTRA_NOTE="绿区外发下载(本人文件)"
  fi
fi

UPSTREAM_INC="$NGINX_SFSS/upstream-$ZONE-$SYS.inc"
cat > "$UPSTREAM_INC" <<EOF
proxy_pass https://$BLUE_IP:8443;
proxy_ssl_server_name on;
proxy_ssl_name $BLUE_HOST;
$( [[ -f "$BLUE_CA" ]] && echo "proxy_ssl_trusted_certificate $BLUE_CA;" || echo "# 无 blue-ca:不校验蓝区(仅试点)" )
proxy_ssl_verify $PROXY_SSL_VERIFY;
$VERIFY_DEPTH
$MTLS_BLOCK
proxy_http_version 1.1;
proxy_request_buffering off;
proxy_buffering off;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
proxy_set_header Host $BLUE_HOST;
proxy_set_header X-SFSS-Zone $ZONE;
proxy_set_header X-Forwarded-For \$remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header Connection "";
EOF

cat > "$CONF" <<EOF
# ${ZONE_HEADER}网关 —— ${EXTRA_NOTE}
# 域名: $DOMAIN  (改 REPLACE_DOMAIN 后同步改 server_name)
limit_req_zone \$binary_remote_addr zone=sfss_api:10m rate=20r/s;
limit_req_zone \$binary_remote_addr zone=sfss_login:10m rate=5r/m;
limit_conn_zone \$binary_remote_addr zone=sfss_client_conn:10m;

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate     $GW_CERT;
    ssl_certificate_key $GW_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 140m;
    client_header_timeout 15s;
    client_body_timeout 3600s;
    limit_conn sfss_client_conn 32;

$(echo "$ROUTES" | sed "s#\$UPSTREAM_INC#$UPSTREAM_INC#g")
}
EOF

if [[ -f /etc/nginx/nginx.conf ]] && ! grep -q "include /etc/nginx/sfss" /etc/nginx/nginx.conf; then
  sed -i '0,/^http {/s//http {\n    include \/etc\/nginx\/sfss\/*.conf;/' /etc/nginx/nginx.conf
fi
if nginx -t 2>/dev/null; then
  nginx -s reload 2>/dev/null || true
  log "nginx 已 reload"
else
  die "nginx -t 失败,检查 $CONF"
fi

log "完成: ${ZONE_HEADER}网关($EXTRA_NOTE)"
log "  对外: https://$DOMAIN  (替换 REPLACE_DOMAIN)"
log "  上游: https://$BLUE_IP:8443 (SNI $BLUE_HOST, $( [[ -f "$CLIENT_CERT" ]] && echo mTLS || echo 试点-仅TLS ))"
[[ -f "$BLUE_CA" ]] || log "  提醒: 生产需放置 $BLUE_CA 与 $BLUE_CRL"

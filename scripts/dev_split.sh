#!/usr/bin/env bash
# SFSS 双系统一键启动/停止脚本(开发模式)
#
# 用法:
#   scripts/dev_split.sh start       [端口in] [端口out]  # 本地账号模式(默认 8081/8082)
#   scripts/dev_split.sh start-ldap  [端口in] [端口out]  # LDAP 登录模式(默认 8081/8082)
#   scripts/dev_split.sh stop | status | restart         # restart 沿用上次模式
#
# 系统 1(inbound): 绿区上传 -> 扫描 -> 红区本人下载      http://127.0.0.1:${IN_PORT}/green
# 系统 2(outbound): 红区上传 -> 审批 -> 绿区本人下载      http://127.0.0.1:${OUT_PORT}/red
#
# 本地模式: admin/admin123, alice/alice123; 首次启动自动启用外发策略并创建审批员 bob/bob12345。
# LDAP 模式: 登录走 LDAP bind(默认 uid={username},ou=People,dc=eryajf,dc=net),首次启动自动
#           配置目录同步(导入 ou=People 用户)、启用外发策略、授予 SFSS_BOOTSTRAP_ADMINS 审批员。
#           需要 Python 环境安装 ldap3: uv pip install --python .venv/bin/python ldap3==2.9.1
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${SFSS_DEV_RUN_DIR:-/tmp/sfss-dev}"
IN_PORT="${2:-8081}"
OUT_PORT="${3:-8082}"

# ---- LDAP 目录参数(可用环境变量覆盖) ----
LDAP_URI="${SFSS_DEV_LDAP_URI:-ldap://localhost:389}"
LDAP_BASE_DN="${SFSS_DEV_LDAP_BASE_DN:-dc=eryajf,dc=net}"
LDAP_USER_TEMPLATE="${SFSS_DEV_LDAP_USER_TEMPLATE:-}"
if [[ -z "$LDAP_USER_TEMPLATE" ]]; then LDAP_USER_TEMPLATE='uid={username},ou=People,{base_dn}'; fi
LDAP_SYNC_BASE_DN="${SFSS_DEV_LDAP_SYNC_BASE_DN:-ou=People,${LDAP_BASE_DN}}"
LDAP_BIND_DN="${SFSS_DEV_LDAP_BIND_DN:-cn=admin,${LDAP_BASE_DN}}"
LDAP_BIND_PASSWORD="${SFSS_DEV_LDAP_BIND_PASSWORD:-123456}"
LDAP_ADMIN_USER="${SFSS_DEV_LDAP_ADMIN_USER:-testuser}"
LDAP_ADMIN_PASSWORD="${SFSS_DEV_LDAP_ADMIN_PASSWORD:-123456}"

inbound_running() { [[ -f "$RUN_DIR/inbound.pid" ]] && kill -0 "$(cat "$RUN_DIR/inbound.pid")" 2>/dev/null; }
outbound_running() { [[ -f "$RUN_DIR/outbound.pid" ]] && kill -0 "$(cat "$RUN_DIR/outbound.pid")" 2>/dev/null; }

api() { curl -sS -m 10 "$@"; }

python_bin() {
  # LDAP 模式依赖 ldap3;优先使用仓库 venv(已安装 ldap3),否则回退系统 python3。
  if [[ "$MODE" == "ldap" && -x "$REPO/.venv/bin/python" ]] && "$REPO/.venv/bin/python" -c "import ldap3" 2>/dev/null; then
    echo "$REPO/.venv/bin/python"
  else
    echo "${PYTHON:-python3}"
  fi
}

start_one() {
  local mode=$1 port=$2 data_dir=$3 log=$4; shift 4
  local py; py="$(python_bin)"
  mkdir -p "$data_dir"
  SFSS_DEPLOYMENT_MODE="$mode" SFSS_DATA_DIR="$data_dir" SFSS_ENVIRONMENT=development \
  PYTHONPATH="$REPO/src" "$@" nohup "$py" -m sfss.server --port "$port" > "$log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "[$mode] 启动失败,日志 $log:"; tail -5 "$log"; exit 1
    fi
    if api "http://127.0.0.1:${port}/health" 2>/dev/null | grep -q '"ok"' && kill -0 "$pid" 2>/dev/null; then
      echo "$pid" > "$RUN_DIR/${mode}.pid"; return 0
    fi
    sleep 0.3
  done
  echo "[$mode] 健康检查超时,日志 $log"; exit 1
}

login_token() { # login_token <port> <user> <password> <zone>
  api -X POST "http://127.0.0.1:$1/v1/auth/login" -H "Content-Type: application/json" \
    -H "X-SFSS-Zone: $4" -d "{\"username\":\"$2\",\"password\":\"$3\"}" 2>/dev/null \
    | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p'
}

do_start() {
  local mode="$1"; mkdir -p "$RUN_DIR"; echo "$mode" > "$RUN_DIR/mode"
  if inbound_running && outbound_running; then
    echo "已在运行: inbound( $(cat "$RUN_DIR/inbound.pid") ) outbound( $(cat "$RUN_DIR/outbound.pid") )"; exit 0
  fi
  if [[ "$mode" == "ldap" ]]; then
    if ! "$(python_bin)" -c "import ldap3" 2>/dev/null; then
      echo "错误: LDAP 模式需要 ldap3,请执行: uv pip install --python .venv/bin/python ldap3==2.9.1"; exit 1
    fi
    start_one inbound "$IN_PORT" "$RUN_DIR/in" "$RUN_DIR/in.log" \
      env SFSS_AUTH_BACKEND=ldap SFSS_LDAP_URI="$LDAP_URI" SFSS_LDAP_BASE_DN="$LDAP_BASE_DN" \
          SFSS_LDAP_USER_TEMPLATE="$LDAP_USER_TEMPLATE" SFSS_BOOTSTRAP_ADMINS="$LDAP_ADMIN_USER" \
          SFSS_LDAP_FALLBACK_ADMIN=admin SFSS_LOCAL_CREDENTIALS=admin:123456
    echo "[inbound]  pid $(cat "$RUN_DIR/inbound.pid")  http://127.0.0.1:${IN_PORT}/green  (LDAP 登录)"
    start_one outbound "$OUT_PORT" "$RUN_DIR/out" "$RUN_DIR/out.log" \
      env SFSS_AUTH_BACKEND=ldap SFSS_LDAP_URI="$LDAP_URI" SFSS_LDAP_BASE_DN="$LDAP_BASE_DN" \
          SFSS_LDAP_USER_TEMPLATE="$LDAP_USER_TEMPLATE" SFSS_BOOTSTRAP_ADMINS="$LDAP_ADMIN_USER" \
          SFSS_LDAP_FALLBACK_ADMIN=admin SFSS_LOCAL_CREDENTIALS=admin:123456
    echo "[outbound] pid $(cat "$RUN_DIR/outbound.pid")  http://127.0.0.1:${OUT_PORT}/red  (LDAP 登录)"
    bootstrap_ldap
    echo
    echo "入口(LDAP 用户直接登录,如 $LDAP_ADMIN_USER):"
    echo "  绿区上传(个人空间)   http://127.0.0.1:${IN_PORT}/green"
    echo "  红区下载(本人文件)   http://127.0.0.1:${IN_PORT}/red"
    echo "  红区外发上传         http://127.0.0.1:${OUT_PORT}/red"
    echo "  绿区下载已放行外发   http://127.0.0.1:${OUT_PORT}/green"
    echo "  管理后台             http://127.0.0.1:${IN_PORT}/admin  http://127.0.0.1:${OUT_PORT}/admin"
    echo "  (LDAP 管理员: $LDAP_ADMIN_USER / 本地兜底管理员: admin/123456 — LDAP 故障时仍可登录管理台)"
  else
    start_one inbound "$IN_PORT" "$RUN_DIR/in" "$RUN_DIR/in.log" env
    echo "[inbound]  pid $(cat "$RUN_DIR/inbound.pid")  http://127.0.0.1:${IN_PORT}/green   (admin/admin123)"
    start_one outbound "$OUT_PORT" "$RUN_DIR/out" "$RUN_DIR/out.log" env
    echo "[outbound] pid $(cat "$RUN_DIR/outbound.pid")  http://127.0.0.1:${OUT_PORT}/red    (alice/alice123)"
    bootstrap_local
    echo
    echo "入口:"
    echo "  绿区上传(个人空间)   http://127.0.0.1:${IN_PORT}/green   (admin/admin123)"
    echo "  红区下载(本人文件)   http://127.0.0.1:${IN_PORT}/red"
    echo "  红区外发上传         http://127.0.0.1:${OUT_PORT}/red    (alice/alice123)"
    echo "  绿区下载已放行外发   http://127.0.0.1:${OUT_PORT}/green  (上传者本人)"
    echo "  管理后台(两系统独立) http://127.0.0.1:${IN_PORT}/admin  http://127.0.0.1:${OUT_PORT}/admin"
  fi
  echo "停止: scripts/dev_split.sh stop"
}

bootstrap_local() {
  local admin token
  admin=$(login_token "$OUT_PORT" admin admin123 admin)
  [[ -n "$admin" ]] || { echo "[outbound] 警告:无法登录管理员,跳过初始化"; return 0; }
  if ! api "http://127.0.0.1:${OUT_PORT}/v1/admin/outbound-policy" -H "Authorization: Bearer $admin" 2>/dev/null | grep -q '"enabled": *1'; then
    api -X PUT "http://127.0.0.1:${OUT_PORT}/v1/admin/outbound-policy" \
      -H "Authorization: Bearer $admin" -H "Content-Type: application/json" \
      -d '{"enabled":true,"approval_provider":"local","allowed_classifications":["GDS","FPGA_BITFILE","GENERAL"],"approval_timeout_hours":24,"download_ttl_hours":24}' > /dev/null
    echo "[outbound] 已启用本地外发策略"
  fi
  if api -X POST "http://127.0.0.1:${OUT_PORT}/v1/admin/users" \
      -H "Authorization: Bearer $admin" -H "Content-Type: application/json" \
      -d '{"username":"bob","password":"bob12345"}' 2>/dev/null | grep -q "bob"; then
    echo "[outbound] 已创建审批员 bob/bob12345"
  else
    echo "[outbound] 审批员 bob/bob12345 已就绪"
  fi
  api -X PUT "http://127.0.0.1:${OUT_PORT}/v1/admin/users/bob/approver" \
    -H "Authorization: Bearer $admin" -H "Content-Type: application/json" \
    -d '{"approver":true}' > /dev/null
}

bootstrap_ldap() {
  # bootstrap 管理员登录(触发 global_admin 授权)
  local token
  token=$(login_token "$OUT_PORT" "$LDAP_ADMIN_USER" "$LDAP_ADMIN_PASSWORD" admin)
  if [[ -z "$token" ]]; then
    echo "[outbound] 警告:LDAP 管理员 $LDAP_ADMIN_USER 登录失败,跳过自动初始化"; return 0
  fi
  # 目录同步配置(用户名属性取 RDN 属性,People 下默认为 uid)
  api -X PUT "http://127.0.0.1:${OUT_PORT}/v1/admin/ldap-sync" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    -d "{\"enabled\":true,\"uri\":\"$LDAP_URI\",\"base_dn\":\"$LDAP_SYNC_BASE_DN\",\"bind_dn\":\"$LDAP_BIND_DN\",\"bind_password\":\"$LDAP_BIND_PASSWORD\",\"username_attribute\":\"uid\",\"deprovision_missing\":false}" > /dev/null
  local summary
  summary=$(api -X POST "http://127.0.0.1:${OUT_PORT}/v1/admin/ldap-sync/run" \
    -H "Authorization: Bearer $token" -H "Content-Length: 0" 2>/dev/null || true)
  echo "[outbound] LDAP 同步: $(echo "$summary" | head -c 200)"
  if ! api "http://127.0.0.1:${OUT_PORT}/v1/admin/outbound-policy" -H "Authorization: Bearer $token" 2>/dev/null | grep -q '"enabled": *1'; then
    api -X PUT "http://127.0.0.1:${OUT_PORT}/v1/admin/outbound-policy" \
      -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
      -d '{"enabled":true,"approval_provider":"local","allowed_classifications":["GDS","FPGA_BITFILE","GENERAL"],"approval_timeout_hours":24,"download_ttl_hours":24}' > /dev/null
  fi
  echo "[outbound] 已启用本地外发策略"
  api -X PUT "http://127.0.0.1:${OUT_PORT}/v1/admin/users/$LDAP_ADMIN_USER/approver" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    -d '{"approver":true}' > /dev/null
  echo "[outbound] 已授予 $LDAP_ADMIN_USER 审批员身份"
  echo "[双系统] 本地兜底管理员 admin/123456 已启用(LDAP 故障时仍可登录管理台)"
}

do_stop() {
  local stopped=0
  for name in inbound outbound; do
    if [[ -f "$RUN_DIR/$name.pid" ]]; then
      local pid; pid=$(cat "$RUN_DIR/$name.pid")
      if kill -0 "$pid" 2>/dev/null; then kill "$pid"; stopped=1; echo "[$name] 已停止 (pid $pid)"; fi
      rm -f "$RUN_DIR/$name.pid"
    fi
  done
  if [[ $stopped -eq 0 ]]; then echo "没有正在运行的实例"; fi
}

do_status() {
  local ok=1
  for name in inbound outbound; do
    local port="$IN_PORT"; [[ "$name" == "outbound" ]] && port="$OUT_PORT"
    if [[ -f "$RUN_DIR/$name.pid" ]] && kill -0 "$(cat "$RUN_DIR/$name.pid")" 2>/dev/null; then
      local health; health=$(api "http://127.0.0.1:${port}/health" 2>/dev/null || true)
      echo "[$name] 运行中 pid $(cat "$RUN_DIR/$name.pid") 端口 $port  ${health:-无响应}"
    else
      echo "[$name] 未运行"; ok=0
    fi
  done
  [[ -f "$RUN_DIR/mode" ]] && echo "模式: $(cat "$RUN_DIR/mode")"
  [[ $ok -eq 1 ]]
}

MODE="local"
case "${1:-}" in
  start)      MODE=local; do_start local ;;
  start-ldap) MODE=ldap; do_start ldap ;;
  stop)       do_stop ;;
  status)     do_status || exit 1 ;;
  restart)
    [[ -f "$RUN_DIR/mode" ]] && MODE="$(cat "$RUN_DIR/mode")"
    do_stop; sleep 1; do_start "$MODE" ;;
  *) echo "用法: $0 {start|start-ldap|stop|status|restart} [inbound端口] [outbound端口]"; exit 1 ;;
esac

#!/usr/bin/env bash
# SFSS 双系统一键启动/停止脚本(开发模式)
#
# 用法:
#   scripts/dev_split.sh start [端口in] [端口out]   # 默认 8081 8082
#   scripts/dev_split.sh stop
#   scripts/dev_split.sh status
#   scripts/dev_split.sh restart
#
# 系统 1(inbound): 绿区上传 -> 扫描 -> 红区本人下载      http://127.0.0.1:${IN_PORT}/green
# 系统 2(outbound): 红区上传 -> 审批 -> 绿区本人下载      http://127.0.0.1:${OUT_PORT}/red
#
# 首次启动会自动为 outbound 系统启用本地外发策略并创建审批员 bob/bob12345。
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${SFSS_DEV_RUN_DIR:-/tmp/sfss-dev}"
IN_PORT="${2:-8081}"
OUT_PORT="${3:-8082}"
PYTHON_BIN="${PYTHON:-python3}"

inbound_running() { [[ -f "$RUN_DIR/inbound.pid" ]] && kill -0 "$(cat "$RUN_DIR/inbound.pid")" 2>/dev/null; }
outbound_running() { [[ -f "$RUN_DIR/outbound.pid" ]] && kill -0 "$(cat "$RUN_DIR/outbound.pid")" 2>/dev/null; }

api() { curl -sS -m 5 "$@"; }

start_one() {
  local mode=$1 port=$2 data_dir=$3 log=$4
  mkdir -p "$data_dir"
  SFSS_DEPLOYMENT_MODE="$mode" SFSS_DATA_DIR="$data_dir" \
  SFSS_ENVIRONMENT=development PYTHONPATH="$REPO/src" \
    nohup "$PYTHON_BIN" -m sfss.server --port "$port" > "$log" 2>&1 &
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

do_start() {
  mkdir -p "$RUN_DIR"
  if inbound_running && outbound_running; then
    echo "已在运行: inbound( $(cat "$RUN_DIR/inbound.pid") ) outbound( $(cat "$RUN_DIR/outbound.pid") )"; exit 0
  fi
  start_one inbound  "$IN_PORT"  "$RUN_DIR/in"  "$RUN_DIR/in.log"
  echo "[inbound]  pid $(cat "$RUN_DIR/inbound.pid")  http://127.0.0.1:${IN_PORT}/green"
  start_one outbound "$OUT_PORT" "$RUN_DIR/out" "$RUN_DIR/out.log"
  echo "[outbound] pid $(cat "$RUN_DIR/outbound.pid")  http://127.0.0.1:${OUT_PORT}/red"
  bootstrap_outbound
  echo
  echo "入口:"
  echo "  绿区上传(个人空间)   http://127.0.0.1:${IN_PORT}/green   (admin/admin123)"
  echo "  红区下载(本人文件)   http://127.0.0.1:${IN_PORT}/red"
  echo "  红区外发上传         http://127.0.0.1:${OUT_PORT}/red    (alice/alice123)"
  echo "  绿区下载已放行外发   http://127.0.0.1:${OUT_PORT}/green  (上传者本人)"
  echo "  管理后台(两系统独立) http://127.0.0.1:${IN_PORT}/admin  http://127.0.0.1:${OUT_PORT}/admin"
  echo "停止: scripts/dev_split.sh stop"
}

bootstrap_outbound() {
  # 首次启动:启用外发策略 + 创建审批员 bob
  local admin token
  admin=$(api -X POST "http://127.0.0.1:${OUT_PORT}/v1/auth/login" \
    -H "Content-Type: application/json" -H "X-SFSS-Zone: admin" \
    -d '{"username":"admin","password":"admin123"}' 2>/dev/null | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
  [[ -n "$admin" ]] || { echo "[outbound] 警告:无法登录管理员,跳过初始化(外发功能需手动启用)"; return 0; }
  if ! api "http://127.0.0.1:${OUT_PORT}/v1/admin/outbound-policy" -H "Authorization: Bearer $admin" 2>/dev/null | grep -q '"enabled": *1'; then
    api -X PUT "http://127.0.0.1:${OUT_PORT}/v1/admin/outbound-policy" \
      -H "Authorization: Bearer $admin" -H "Content-Type: application/json" \
      -d '{"enabled":true,"approval_provider":"local","allowed_classifications":["GDS","FPGA_BITFILE","GENERAL"],"approval_timeout_hours":24,"download_ttl_hours":24}' > /dev/null
    echo "[outbound] 已启用本地外发策略"
  fi
  if ! api -X POST "http://127.0.0.1:${OUT_PORT}/v1/admin/users" \
      -H "Authorization: Bearer $admin" -H "Content-Type: application/json" \
      -d '{"username":"bob","password":"bob12345"}' 2>/dev/null | grep -q "bob"; then
    api -X PUT "http://127.0.0.1:${OUT_PORT}/v1/admin/users/bob/approver" \
      -H "Authorization: Bearer $admin" -H "Content-Type: application/json" \
      -d '{"approver":true}' > /dev/null
    echo "[outbound] 审批员 bob/bob12345 已就绪"
  else
    api -X PUT "http://127.0.0.1:${OUT_PORT}/v1/admin/users/bob/approver" \
      -H "Authorization: Bearer $admin" -H "Content-Type: application/json" \
      -d '{"approver":true}' > /dev/null
    echo "[outbound] 已创建审批员 bob/bob12345"
  fi
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
  [[ $ok -eq 1 ]]
}

case "${1:-}" in
  start)   do_start ;;
  stop)    do_stop ;;
  status)  do_status || exit 1 ;;
  restart) do_stop; sleep 1; do_start ;;
  *) echo "用法: $0 {start|stop|status|restart} [inbound端口] [outbound端口]"; exit 1 ;;
esac

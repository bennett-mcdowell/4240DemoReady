#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_SRC="$ROOT_DIR/src"
DEMO_DIR="/var/lib/sshguard-dashboard-demo"
DEMO_LOG="$DEMO_DIR/auth.log"
DEMO_CONFIG="$DEMO_DIR/config.json"
DEMO_PID_FILE="$DEMO_DIR/demo.pid"
DEMO_IP_DEFAULT="172.16.10.77"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

ensure_sudo() {
  if [[ "${EUID}" -ne 0 ]]; then
    need_cmd sudo
    exec sudo "$0" "$@"
  fi
}

setup_demo_files() {
  mkdir -p "$DEMO_DIR"
  chmod 700 "$DEMO_DIR"

  if [[ -L "$DEMO_LOG" || -L "$DEMO_CONFIG" || -L "$DEMO_PID_FILE" ]]; then
    echo "Refusing to run: demo files must not be symlinks" >&2
    exit 1
  fi

  : > "$DEMO_LOG"
  chmod 600 "$DEMO_LOG"

  # Preserve existing config across restarts; initialize only once.
  if [[ ! -f "$DEMO_CONFIG" ]]; then
    cat > "$DEMO_CONFIG" <<'EOF'
{
  "threshold": 5,
  "window_seconds": 300,
  "log_path": "/var/lib/sshguard-dashboard-demo/auth.log",
  "whitelist": []
}
EOF
    chmod 600 "$DEMO_CONFIG"
  fi
}

remove_stale_pid() {
  if [[ -f "$DEMO_PID_FILE" ]]; then
    local pid
    pid="$(cat "$DEMO_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      local cmdline
      cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
      if [[ "$cmdline" == *"sshguard_dashboard"* ]] && [[ "$cmdline" == *"$PROJECT_SRC"* ]]; then
        return
      fi
    fi
    rm -f "$DEMO_PID_FILE"
  fi
}

stop_services() {
  remove_stale_pid

  if [[ ! -f "$DEMO_PID_FILE" ]]; then
    echo "No tracked demo process is running"
    return
  fi

  local pid
  pid="$(cat "$DEMO_PID_FILE")"

  if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    echo "Invalid PID file contents; refusing to signal" >&2
    rm -f "$DEMO_PID_FILE"
    exit 1
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$DEMO_PID_FILE"
    echo "Removed stale PID file"
    return
  fi

  local cmdline
  cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
  if [[ "$cmdline" != *"sshguard_dashboard"* ]] || [[ "$cmdline" != *"$PROJECT_SRC"* ]]; then
    echo "PID $pid does not appear to be this demo process; refusing to kill" >&2
    exit 1
  fi

  kill "$pid" 2>/dev/null || true

  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done

  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi

  rm -f "$DEMO_PID_FILE"
  echo "Stopped demo process (pid $pid)"
}

start_demo() {
  need_cmd python3
  need_cmd fuser
  need_cmd pkill

  remove_stale_pid

  if [[ -f "$DEMO_PID_FILE" ]]; then
    echo "Demo appears to already be running (pid: $(cat "$DEMO_PID_FILE"))."
    echo "Run ./demo.sh stop first, or remove $DEMO_PID_FILE if stale."
    exit 1
  fi

  setup_demo_files

  echo "Starting SSHBlock demo on http://127.0.0.1:5000"
  echo "Config: $DEMO_CONFIG"
  echo "Log:    $DEMO_LOG"
  echo "PID:    $DEMO_PID_FILE"

  export SSHGUARD_DEMO_PID_FILE="$DEMO_PID_FILE"
  export SSHGUARD_DEMO_CONFIG_FILE="$DEMO_CONFIG"

  PYTHONPATH="$PROJECT_SRC" python3 <<'PY'
import atexit
import os

from sshguard_dashboard.config import load_config
from sshguard_dashboard.daemon import SSHBlockDaemon
from sshguard_dashboard import web

pid_file = os.environ.get("SSHGUARD_DEMO_PID_FILE")
config_file = os.environ.get("SSHGUARD_DEMO_CONFIG_FILE")

if not pid_file or not config_file:
  raise RuntimeError("Missing required demo environment variables")

with open(pid_file, "w", encoding="utf-8") as f:
    f.write(str(os.getpid()))


def _cleanup_pid() -> None:
    try:
        if os.path.exists(pid_file):
            os.remove(pid_file)
    except OSError:
        pass


atexit.register(_cleanup_pid)

cfg = load_config(config_file)
d = SSHBlockDaemon(config=cfg)
web.threshold_tracker = d.threshold_tracker
web.blocked_ip_store = d.blocked_ip_store
web.set_daemon(d)
d.start()
web.run_server(host='127.0.0.1', port=5000, use_gevent=True)
PY
}

inject_attacks() {
  local ip="${1:-$DEMO_IP_DEFAULT}"
  local count="${2:-5}"

  need_cmd tee

  if [[ ! "$count" =~ ^[0-9]+$ ]] || [[ "$count" -lt 1 ]]; then
    echo "Count must be a positive integer" >&2
    exit 1
  fi

  if [[ "$count" -gt 1000 ]]; then
    echo "Count too large (max 1000)" >&2
    exit 1
  fi

  if ! python3 - <<PY >/dev/null 2>&1
import ipaddress
ipaddress.ip_address("$ip")
PY
  then
    echo "Invalid IP address: $ip" >&2
    exit 1
  fi

  for i in $(seq 1 "$count"); do
    local ts
    ts="$(date '+%b %e %H:%M:%S')"
    printf '%s host sshd[%d]: Failed password for admin from %s port 22 ssh2\n' "$ts" "$((6000 + i))" "$ip" | tee -a "$DEMO_LOG" >/dev/null
    sleep 0.5
  done

  echo "Injected $count failed attempts for $ip"
}

status_demo() {
  need_cmd curl
  need_cmd ss

  echo "== Listener =="
  ss -ltnp | grep ':5000' || echo "No listener on :5000"

  echo
  echo "== API: blocked-ips =="
  curl -s http://127.0.0.1:5000/api/blocked-ips | head || true

  echo
  echo "== API: stats =="
  curl -s http://127.0.0.1:5000/api/stats | head || true

  echo
  echo "== API: stats/graph =="
  curl -s http://127.0.0.1:5000/api/stats/graph | head || true
}

open_browser() {
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open http://127.0.0.1:5000/ >/dev/null 2>&1 || true
  else
    echo "Open this URL manually: http://127.0.0.1:5000/"
  fi
}

usage() {
  cat <<'EOF'
Usage:
  ./demo.sh start                      Start daemon+dashboard (foreground)
  ./demo.sh stop                      Stop demo services
  ./demo.sh attack [ip] [count]       Inject failed SSH attempts (default ip, count=5)
  ./demo.sh status                    Check listener and API responses
  ./demo.sh open                      Open dashboard URL

Examples:
  ./demo.sh start
  ./demo.sh attack 10.0.0.50 5
  ./demo.sh status
EOF
}

main() {
  local cmd="${1:-}"

  case "$cmd" in
    start)
      ensure_sudo "$@"
      if [[ $# -ne 1 ]]; then
        echo "Invalid arguments for start" >&2
        usage
        exit 1
      fi
      start_demo
      ;;
    stop)
      ensure_sudo "$@"
      stop_services
      echo "Stopped demo services"
      ;;
    attack)
      ensure_sudo "$@"
      if [[ $# -gt 3 ]]; then
        echo "Too many arguments for attack" >&2
        usage
        exit 1
      fi
      inject_attacks "${2:-$DEMO_IP_DEFAULT}" "${3:-5}"
      ;;
    status)
      status_demo
      ;;
    open)
      open_browser
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"

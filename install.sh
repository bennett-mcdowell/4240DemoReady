#!/bin/bash
set -e

# SSHBlock Dashboard Installation Script
# Requires: Python 3.10+, systemd, iptables, root privileges

APP_DIR="/opt/sshguard-dashboard"
VENV_DIR="$APP_DIR/venv"
PYTHON_BIN="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"
GUNICORN_BIN="$VENV_DIR/bin/gunicorn"

echo "SSHBlock Dashboard Installer"
echo "=============================="
echo

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: This script must be run as root"
  echo "Usage: sudo ./install.sh"
  exit 1
fi

# Check for Python 3.10+
if ! command -v python3 &> /dev/null; then
  echo "ERROR: python3 not found"
  echo "Install Python 3.10 or newer first"
  exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "$(printf '%s\n' "3.10" "$PYTHON_VERSION" | sort -V | head -n1)" != "3.10" ]; then
  echo "ERROR: Python 3.10 or newer required (found $PYTHON_VERSION)"
  exit 1
fi

# Check for systemd
if ! command -v systemctl &> /dev/null; then
  echo "ERROR: systemd not found"
  echo "This tool requires systemd for service management"
  exit 1
fi

# Check for iptables
if ! command -v iptables &> /dev/null; then
  echo "ERROR: iptables not found"
  echo "Install iptables first: apt-get install iptables"
  exit 1
fi

if ! python3 -m venv "$VENV_DIR" >/dev/null 2>&1; then
  echo "ERROR: python3-venv is not available"
  echo "Install the venv package for your distribution, then rerun install.sh"
  exit 1
fi

echo "✓ All prerequisites met"
echo

# Install Python package
echo "Installing Python package in virtual environment..."
"$PYTHON_BIN" -m pip install --upgrade pip >/dev/null
"$PIP_BIN" install . || {
  echo "ERROR: Failed to install Python package"
  exit 1
}
echo "✓ Python package installed"
echo

# Create directories per DEP-03
echo "Creating directories..."
mkdir -p /etc/sshguard-dashboard
mkdir -p /var/lib/sshguard-dashboard
mkdir -p /usr/share/doc/sshguard-dashboard
echo "✓ Directories created"
echo

# Set permissions per DEP-03
echo "Setting permissions..."
chmod 755 /etc/sshguard-dashboard
chmod 755 /var/lib/sshguard-dashboard
chmod 755 /usr/share/doc/sshguard-dashboard
echo "✓ Permissions set"
echo

# Create default config if not exists
CONFIG_FILE="/etc/sshguard-dashboard/config.json"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Creating default config at $CONFIG_FILE..."
  cat > "$CONFIG_FILE" << 'EOF'
{
  "threshold": 5,
  "window_seconds": 300,
  "log_path": "/var/log/auth.log",
  "whitelist": ["127.0.0.1", "::1"]
}
EOF
  chmod 644 "$CONFIG_FILE"
  echo "✓ Default config created"
else
  echo "✓ Config file already exists (not modified)"
fi
echo

# Initialize blocked IPs file if not exists
BLOCKED_IPS_FILE="/var/lib/sshguard-dashboard/blocked_ips.json"
if [ ! -f "$BLOCKED_IPS_FILE" ]; then
  echo "Initializing blocked IPs file..."
  echo '{"blocked_ips": []}' > "$BLOCKED_IPS_FILE"
  chmod 644 "$BLOCKED_IPS_FILE"
  echo "✓ Blocked IPs file initialized"
else
  echo "✓ Blocked IPs file already exists (not modified)"
fi
echo

# Install systemd service files
rewrite_execstart() {
  local file="$1"
  local old_line="$2"
  local new_line="$3"

  python3 - "$file" "$old_line" "$new_line" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old_line = sys.argv[2]
new_line = sys.argv[3]
text = path.read_text(encoding="utf-8")
if old_line not in text:
    raise SystemExit(f"Expected ExecStart pattern not found in {path}")
path.write_text(text.replace(old_line, new_line, 1), encoding="utf-8")
PY
}

echo "Installing systemd service files..."
cp systemd/sshguard-dashboard.service /etc/systemd/system/
cp systemd/sshguard-web.service /etc/systemd/system/
rewrite_execstart \
  /etc/systemd/system/sshguard-dashboard.service \
  "/usr/bin/python3 -m sshguard_dashboard.daemon -c /etc/sshguard-dashboard/config.json" \
  "$PYTHON_BIN -m sshguard_dashboard.daemon -c /etc/sshguard-dashboard/config.json"
rewrite_execstart \
  /etc/systemd/system/sshguard-web.service \
  "/usr/bin/gunicorn --bind 127.0.0.1:5000 --worker-class gevent --workers 1 --log-file - sshguard_dashboard.web:app" \
  "$GUNICORN_BIN --bind 127.0.0.1:5000 --worker-class gevent --workers 1 --log-file - sshguard_dashboard.web:app"
chmod 644 /etc/systemd/system/sshguard-dashboard.service
chmod 644 /etc/systemd/system/sshguard-web.service
echo "✓ Service files installed"
echo

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload
echo "✓ Systemd reloaded"
echo

# Copy documentation
echo "Installing documentation..."
cp README.md /usr/share/doc/sshguard-dashboard/
cp USAGE.md /usr/share/doc/sshguard-dashboard/
chmod 644 /usr/share/doc/sshguard-dashboard/*.md
echo "✓ Documentation installed"
echo

echo "=============================="
echo "Installation complete!"
echo
echo "Next steps:"
echo "1. Review config: /etc/sshguard-dashboard/config.json"
echo "2. Enable services: sudo systemctl enable sshguard-dashboard sshguard-web"
echo "3. Start services: sudo systemctl start sshguard-dashboard sshguard-web"
echo "4. Check status: sudo systemctl status sshguard-dashboard"
echo "5. Access dashboard: http://127.0.0.1:5000"
echo "   (Use SSH tunnel if accessing remotely)"
echo
echo "Documentation: /usr/share/doc/sshguard-dashboard/"
echo "Configuration: /etc/sshguard-dashboard/config.json"
echo "Data directory: /var/lib/sshguard-dashboard/"
echo "Virtual environment: $VENV_DIR"
echo
echo "IMPORTANT: Add your management IP to the whitelist before enabling!"
echo "Edit /etc/sshguard-dashboard/config.json and add your IP to the whitelist array."

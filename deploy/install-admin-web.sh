#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly WEB_TARGET=/usr/local/libexec/secrets-broker-admin-web
readonly CONFIG_DIR=/etc/secrets-broker-admin
readonly CONFIG_TARGET=/etc/secrets-broker-admin/web.toml
readonly SOCKET_PATH=/run/secrets-broker-admin.sock
readonly SOCKET_UNIT=secrets-broker-admin-web.socket
readonly SERVICE_UNIT=secrets-broker-admin-web.service
readonly UNIT_DIR=/etc/systemd/system

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
web_source="$repo_root/bin/secrets-broker-admin-web"
config_source=""
mode="${1:-}"
if [[ -n "$mode" ]]; then shift; fi

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage:
  sudo deploy/install-admin-web.sh install --config PATH [--web PATH]
  sudo deploy/install-admin-web.sh check

Initial TOML configuration requires host and login. Existing configuration is
preserved. This role starts only its root-only Unix socket. Configure private
Tailscale Serve explicitly after installation and verify phone identity.
EOF
}

regular() { [[ -f "$1" && ! -L "$1" ]] || fail "expected a regular non-symlink file: $1"; }
metadata() {
  regular "$1"
  [[ "$(stat -c '%u:%g:%a' "$1")" == "0:0:$2" ]] || fail "unsafe owner or mode: $1"
}

check_directory() {
  [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || fail "unsafe configuration directory"
  [[ "$(stat -c '%u:%g:%a' "$CONFIG_DIR")" == 0:0:700 ]] || fail "unsafe configuration directory owner or mode"
}

check_web() {
  check_directory
  metadata "$CONFIG_TARGET" 600
  metadata "$WEB_TARGET" 700
  for unit in "$SOCKET_UNIT" "$SERVICE_UNIT"; do
    metadata "$UNIT_DIR/$unit" 644
    cmp -s "$UNIT_DIR/$unit" "$script_dir/$unit" || fail "installed unit differs: $unit"
  done
  "$WEB_TARGET" check
  systemd-analyze verify "$UNIT_DIR/$SOCKET_UNIT" "$UNIT_DIR/$SERVICE_UNIT"
  systemctl is-enabled --quiet "$SOCKET_UNIT" || fail "administrator socket is not enabled"
  systemctl is-active --quiet "$SOCKET_UNIT" || fail "administrator socket is not active"
  [[ -S "$SOCKET_PATH" && ! -L "$SOCKET_PATH" ]] || fail "administrator socket is absent"
  [[ "$(stat -c '%u:%g:%a' "$SOCKET_PATH")" == 0:0:600 ]] || fail "unsafe administrator socket"
  [[ "$(systemctl show --value --property=User "$SERVICE_UNIT")" == root ]] || fail "service must run as root"
  [[ "$(systemctl show --value --property=Group "$SERVICE_UNIT")" == root ]] || fail "service group must be root"
  printf '%s\n' 'Admin web socket check passed.'
}

install_web() {
  regular "$web_source"
  [[ -x "$web_source" ]] || fail "web source is not executable"
  for unit in "$SOCKET_UNIT" "$SERVICE_UNIT"; do regular "$script_dir/$unit"; done
  if [[ -e "$CONFIG_DIR" || -L "$CONFIG_DIR" ]]; then check_directory; fi
  if [[ -e "$CONFIG_TARGET" || -L "$CONFIG_TARGET" ]]; then
    metadata "$CONFIG_TARGET" 600
    config_source="$CONFIG_TARGET"
    printf '%s\n' 'Preserved existing admin web configuration.'
  else
    [[ -n "$config_source" ]] || fail "--config is required on first install"
    regular "$config_source"
  fi
  "$web_source" validate < "$config_source"
  for target in "$WEB_TARGET" "$UNIT_DIR/$SOCKET_UNIT" "$UNIT_DIR/$SERVICE_UNIT"; do
    [[ ! -L "$target" ]] || fail "refusing symlink target: $target"
  done
  if systemctl is-active --quiet "$SOCKET_UNIT"; then systemctl stop "$SOCKET_UNIT"; fi
  if systemctl is-active --quiet "$SERVICE_UNIT"; then systemctl stop "$SERVICE_UNIT"; fi
  install -d -o root -g root -m 0700 "$CONFIG_DIR"
  if [[ ! -e "$CONFIG_TARGET" ]]; then install -o root -g root -m 0600 "$config_source" "$CONFIG_TARGET"; fi
  install -D -o root -g root -m 0700 "$web_source" "$WEB_TARGET"
  for unit in "$SOCKET_UNIT" "$SERVICE_UNIT"; do
    install -o root -g root -m 0644 "$script_dir/$unit" "$UNIT_DIR/$unit"
  done
  systemd-analyze verify "$UNIT_DIR/$SOCKET_UNIT" "$UNIT_DIR/$SERVICE_UNIT"
  systemctl daemon-reload
  systemctl enable --quiet "$SOCKET_UNIT"
  systemctl restart "$SOCKET_UNIT"
  check_web
  printf '%s\n' 'Next: configure private Tailscale Serve for unix:/run/secrets-broker-admin.sock and verify the phone identity.'
}

case "$mode" in
  -h|--help|help) usage; exit 0 ;;
  install|check) (( EUID == 0 )) || fail "run this command as root" ;;
  *) usage >&2; exit 2 ;;
esac
while (($#)); do
  case "$1" in
    --config) (($# >= 2)) || fail "--config requires a value"; config_source="$2"; shift 2 ;;
    --web) (($# >= 2)) || fail "--web requires a value"; web_source="$2"; shift 2 ;;
    *) fail "unknown option: $1" ;;
  esac
done
for command_name in install stat cmp systemctl systemd-analyze tailscale; do
  command -v "$command_name" >/dev/null || fail "required command not found: $command_name"
done
case "$mode" in
  install) install_web ;;
  check) check_web ;;
esac

#!/usr/bin/env bash

set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly RELAY_TARGET=/usr/local/bin/secrets-broker-relay
readonly CONFIG_DIR=/etc/secrets-broker-relay
readonly ENV_TARGET=/etc/secrets-broker-relay/environment
readonly SERVICE_TARGET=/etc/systemd/system/secrets-broker-relay.service
readonly SERVICE_NAME=secrets-broker-relay.service

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

mode="${1:-}"
if [[ -n "$mode" ]]; then
  shift
fi

relay_source="$repo_root/bin/secrets-broker-relay"
service_source="$script_dir/secrets-broker-relay.service"
environment_source=""
CONTROL_ADDR=""
DECISION_ADDR=""

usage() {
  cat <<'EOF'
Usage:
  sudo deploy/install-relay.sh install --environment PATH [options]
  sudo deploy/install-relay.sh check

Install options:
  --relay PATH        Relay binary (default: bin/secrets-broker-relay)
  --service PATH      Systemd unit (default: deploy/secrets-broker-relay.service)
  --environment PATH  Initial listener configuration; required on first install

An existing /etc/secrets-broker-relay/environment is always preserved. Edit it
explicitly as root when listener addresses must change.
EOF
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '%s\n' "$*"
}

require_root() {
  (( EUID == 0 )) || fail "run this command as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_source_file() {
  local path="$1"
  local label="$2"

  [[ -f "$path" && ! -L "$path" ]] || fail "$label must be a regular, non-symlink file: $path"
}

require_executable_source() {
  require_source_file "$1" "$2"
  [[ -x "$1" ]] || fail "$2 is not executable: $1"
}

check_regular_file() {
  local path="$1"
  local owner="$2"
  local group="$3"
  local mode_bits="$4"

  [[ -f "$path" && ! -L "$path" ]] || fail "expected a regular, non-symlink file: $path"
  [[ "$(stat -c %U "$path")" == "$owner" ]] || fail "$path has unexpected owner"
  [[ "$(stat -c %G "$path")" == "$group" ]] || fail "$path has unexpected group"
  [[ "$(stat -c %a "$path")" == "$mode_bits" ]] || fail "$path must have mode $mode_bits"
}

validate_ipv4_listener() {
  local value="$1"
  local expected_port="$2"
  local label="$3"
  local first
  local second
  local third
  local fourth
  local port

  [[ "$value" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,5})$ ]] ||
    fail "$label must use a literal Tailscale IPv4 address and port $expected_port"
  first="${BASH_REMATCH[1]}"
  second="${BASH_REMATCH[2]}"
  third="${BASH_REMATCH[3]}"
  fourth="${BASH_REMATCH[4]}"
  port="${BASH_REMATCH[5]}"

  (( 10#$first <= 255 && 10#$second <= 255 && 10#$third <= 255 && 10#$fourth <= 255 )) ||
    fail "$label contains an invalid IPv4 address"
  [[ "$port" == "$expected_port" ]] || fail "$label must use port $expected_port"
  (( 10#$first == 100 && 10#$second >= 64 && 10#$second <= 127 )) ||
    fail "$label must use a Tailscale IPv4 address in 100.64.0.0/10"
}

validate_environment() {
  local path="$1"
  local line
  local control_seen=0
  local decision_seen=0
  local control_ip
  local decision_ip

  require_source_file "$path" "relay environment"
  CONTROL_ADDR=""
  DECISION_ADDR=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    case "$line" in
      CONTROL_ADDR=*)
        (( control_seen == 0 )) || fail "relay environment contains duplicate CONTROL_ADDR"
        [[ "$line" =~ ^CONTROL_ADDR=([^[:space:]#]+)$ ]] || fail "invalid CONTROL_ADDR assignment"
        CONTROL_ADDR="${BASH_REMATCH[1]}"
        control_seen=1
        ;;
      DECISION_ADDR=*)
        (( decision_seen == 0 )) || fail "relay environment contains duplicate DECISION_ADDR"
        [[ "$line" =~ ^DECISION_ADDR=([^[:space:]#]+)$ ]] || fail "invalid DECISION_ADDR assignment"
        DECISION_ADDR="${BASH_REMATCH[1]}"
        decision_seen=1
        ;;
      *)
        fail "relay environment contains an unsupported line"
        ;;
    esac
  done <"$path"

  (( control_seen == 1 )) || fail "relay environment is missing CONTROL_ADDR"
  (( decision_seen == 1 )) || fail "relay environment is missing DECISION_ADDR"
  validate_ipv4_listener "$CONTROL_ADDR" 7620 CONTROL_ADDR
  validate_ipv4_listener "$DECISION_ADDR" 7621 DECISION_ADDR
  control_ip="${CONTROL_ADDR%:*}"
  decision_ip="${DECISION_ADDR%:*}"
  [[ "$control_ip" == "$decision_ip" ]] || fail "relay listeners must use the same Tailscale IP"
}

parse_args() {
  while (($#)); do
    case "$1" in
      --relay)
        (($# >= 2)) || fail "--relay requires a value"
        relay_source="$2"
        shift 2
        ;;
      --service)
        (($# >= 2)) || fail "--service requires a value"
        service_source="$2"
        shift 2
        ;;
      --environment)
        (($# >= 2)) || fail "--environment requires a value"
        environment_source="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done
}

install_relay() {
  for command_name in install stat systemctl systemd-analyze curl grep cmp; do
    require_command "$command_name"
  done

  require_executable_source "$relay_source" "relay source"
  require_source_file "$service_source" "systemd service source"

  if [[ -e "$ENV_TARGET" || -L "$ENV_TARGET" ]]; then
    [[ -f "$ENV_TARGET" && ! -L "$ENV_TARGET" ]] || fail "refusing unsafe existing environment: $ENV_TARGET"
    validate_environment "$ENV_TARGET"
    note "Preserved existing relay environment at $ENV_TARGET."
  else
    [[ -n "$environment_source" ]] || fail "--environment is required on the first install"
    validate_environment "$environment_source"
  fi

  install -d -o root -g root -m 0755 "$CONFIG_DIR"
  if [[ ! -e "$ENV_TARGET" && ! -L "$ENV_TARGET" ]]; then
    install -o root -g root -m 0644 "$environment_source" "$ENV_TARGET"
    note "Installed relay environment at $ENV_TARGET."
  else
    chown root:root "$ENV_TARGET"
    chmod 0644 "$ENV_TARGET"
  fi

  install -D -o root -g root -m 0755 "$relay_source" "$RELAY_TARGET"
  install -o root -g root -m 0644 "$service_source" "$SERVICE_TARGET"
  systemd-analyze verify "$SERVICE_TARGET" >/dev/null 2>&1 || fail "systemd rejected $SERVICE_TARGET"
  systemctl daemon-reload
  systemctl enable --quiet "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"

  check_relay
}

check_relay() {
  for command_name in stat systemctl systemd-analyze curl grep cmp; do
    require_command "$command_name"
  done

  [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || fail "expected a non-symlink directory: $CONFIG_DIR"
  [[ "$(stat -c %U "$CONFIG_DIR")" == root && "$(stat -c %G "$CONFIG_DIR")" == root ]] ||
    fail "$CONFIG_DIR must be owned by root:root"
  [[ "$(stat -c %a "$CONFIG_DIR")" == 755 ]] || fail "$CONFIG_DIR must have mode 755"
  check_regular_file "$RELAY_TARGET" root root 755
  check_regular_file "$ENV_TARGET" root root 644
  check_regular_file "$SERVICE_TARGET" root root 644
  validate_environment "$ENV_TARGET"
  cmp -s "$SERVICE_TARGET" "$service_source" || fail "$SERVICE_TARGET differs from the bundled service"
  systemd-analyze verify "$SERVICE_TARGET" >/dev/null 2>&1 || fail "systemd rejected $SERVICE_TARGET"
  systemctl is-enabled --quiet "$SERVICE_NAME" || fail "$SERVICE_NAME is not enabled"
  systemctl is-active --quiet "$SERVICE_NAME" || fail "$SERVICE_NAME is not active"
  curl --noproxy '*' --fail --silent --max-time 5 "http://$DECISION_ADDR/" 2>/dev/null |
    grep -Fq '<h1>Pending approvals</h1>' || fail "relay decision dashboard did not pass its local health check"

  note "Relay check passed."
  note "The service is enabled, active, and serving the decision dashboard."
}

case "$mode" in
  install)
    require_root
    parse_args "$@"
    install_relay
    ;;
  check)
    require_root
    parse_args "$@"
    check_relay
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

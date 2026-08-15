#!/usr/bin/env bash

set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly WORKER_USER=secrets-broker
readonly RUNNER_USER=secrets-broker-runner
readonly CLIENT_GROUP=secrets-broker-clients
readonly WORKER_HOME=/var/lib/secrets-broker
readonly RUNNER_HOME=/var/lib/secrets-broker-runner
readonly CLI_TARGET=/usr/local/bin/secrets-broker
readonly WORKER_TARGET=/usr/local/libexec/secrets-broker-worker
readonly BWS_TARGET=/usr/local/bin/bws
readonly POLICY_TARGET=/etc/secrets-broker/policy.toml
readonly SUDOERS_TARGET=/etc/sudoers.d/secrets-broker
readonly LOGROTATE_TARGET=/etc/logrotate.d/secrets-broker
readonly AUDIT_DIR=/var/log/secrets-broker
readonly AUDIT_FILE=/var/log/secrets-broker/audit.jsonl
readonly TOKEN_FILE=/var/lib/secrets-broker/bws-access-token

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

mode="${1:-}"
if [[ -n "$mode" ]]; then
  shift
fi

client_user=""
cli_source="$repo_root/bin/secrets-broker"
worker_source="$repo_root/bin/secrets-broker-worker"
bws_source=""
policy_source="$repo_root/policy.example.toml"
sudoers_source="$script_dir/secrets-broker.sudoers"
logrotate_source="$script_dir/secrets-broker.logrotate"

usage() {
  cat <<'EOF'
Usage:
  sudo deploy/install-worker.sh install --client-user USER [options]
  sudo deploy/install-worker.sh check --client-user USER

Install options:
  --cli PATH       Agent-facing CLI (default: bin/secrets-broker)
  --worker PATH    Fixed worker binary (default: bin/secrets-broker-worker)
  --bws PATH       Bitwarden bws binary; required when not already installed
  --policy PATH    Initial policy, installed only when no policy exists
  --sudoers PATH   Sudoers policy (default: deploy/secrets-broker.sudoers)

The installer never creates or replaces the BWS token and never replaces an
existing project policy. Bundled sudoers and audit-rotation policies are
updated on install. Run check after configuring the token and project policy.
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

account_fields() {
  local name="$1"
  local entry

  entry="$(getent passwd "$name")" || fail "account does not exist: $name"
  IFS=: read -r _ _ ACCOUNT_UID ACCOUNT_GID _ ACCOUNT_HOME ACCOUNT_SHELL <<<"$entry"
}

ensure_group() {
  local name="$1"

  if ! getent group "$name" >/dev/null; then
    groupadd --system "$name"
  fi
}

ensure_service_account() {
  local name="$1"
  local home="$2"
  local nologin_shell="$3"
  local primary_group

  if ! getent passwd "$name" >/dev/null; then
    useradd --system --gid "$name" --create-home --home-dir "$home" --shell "$nologin_shell" "$name"
  fi

  account_fields "$name"
  primary_group="$(getent group "$ACCOUNT_GID" | cut -d: -f1)"
  [[ "$primary_group" == "$name" ]] || fail "$name must use $name as its primary group"
  [[ "$ACCOUNT_HOME" == "$home" ]] || fail "$name has unexpected home: $ACCOUNT_HOME"
  [[ "$ACCOUNT_SHELL" == "$nologin_shell" ]] || fail "$name has unexpected shell: $ACCOUNT_SHELL"
}

check_service_account() {
  local name="$1"
  local home="$2"
  local nologin_shell="$3"
  local primary_group

  getent group "$name" >/dev/null || fail "group does not exist: $name"
  account_fields "$name"
  primary_group="$(getent group "$ACCOUNT_GID" | cut -d: -f1)"
  [[ "$primary_group" == "$name" ]] || fail "$name must use $name as its primary group"
  [[ "$ACCOUNT_HOME" == "$home" ]] || fail "$name has unexpected home: $ACCOUNT_HOME"
  [[ "$ACCOUNT_SHELL" == "$nologin_shell" ]] || fail "$name has unexpected shell: $ACCOUNT_SHELL"
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

check_directory() {
  local path="$1"
  local owner="$2"
  local group="$3"
  local mode_bits="$4"

  [[ -d "$path" && ! -L "$path" ]] || fail "expected a non-symlink directory: $path"
  [[ "$(stat -c %U "$path")" == "$owner" ]] || fail "$path has unexpected owner"
  [[ "$(stat -c %G "$path")" == "$group" ]] || fail "$path has unexpected group"
  [[ "$(stat -c %a "$path")" == "$mode_bits" ]] || fail "$path must have mode $mode_bits"
}

parse_args() {
  while (($#)); do
    case "$1" in
      --client-user)
        (($# >= 2)) || fail "--client-user requires a value"
        client_user="$2"
        shift 2
        ;;
      --cli)
        (($# >= 2)) || fail "--cli requires a value"
        cli_source="$2"
        shift 2
        ;;
      --worker)
        (($# >= 2)) || fail "--worker requires a value"
        worker_source="$2"
        shift 2
        ;;
      --bws)
        (($# >= 2)) || fail "--bws requires a value"
        bws_source="$2"
        shift 2
        ;;
      --policy)
        (($# >= 2)) || fail "--policy requires a value"
        policy_source="$2"
        shift 2
        ;;
      --sudoers)
        (($# >= 2)) || fail "--sudoers requires a value"
        sudoers_source="$2"
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

  [[ -n "$client_user" ]] || fail "--client-user is required"
  getent passwd "$client_user" >/dev/null || fail "client account does not exist: $client_user"
  account_fields "$client_user"
  [[ "$ACCOUNT_UID" != 0 && "$client_user" != "$WORKER_USER" && "$client_user" != "$RUNNER_USER" ]] ||
    fail "client account must be a non-root human account"
}

install_worker() {
  local nologin_shell
  local client_home
  local sudoers_tmp

  for command_name in getent groupadd useradd usermod install stat visudo setfacl logrotate cut; do
    require_command "$command_name"
  done

  require_executable_source "$cli_source" "CLI source"
  require_executable_source "$worker_source" "worker source"
  require_source_file "$policy_source" "policy source"
  require_source_file "$sudoers_source" "sudoers source"
  require_source_file "$logrotate_source" "logrotate source"
  if [[ -e "$POLICY_TARGET" || -L "$POLICY_TARGET" ]]; then
    [[ -f "$POLICY_TARGET" && ! -L "$POLICY_TARGET" ]] || fail "refusing unsafe existing policy: $POLICY_TARGET"
  fi
  if [[ -e "$LOGROTATE_TARGET" || -L "$LOGROTATE_TARGET" ]]; then
    [[ -f "$LOGROTATE_TARGET" && ! -L "$LOGROTATE_TARGET" ]] ||
      fail "refusing unsafe existing logrotate policy: $LOGROTATE_TARGET"
  fi
  if [[ -n "$bws_source" ]]; then
    require_executable_source "$bws_source" "bws source"
  elif [[ ! -f "$BWS_TARGET" || -L "$BWS_TARGET" || ! -x "$BWS_TARGET" ]]; then
    fail "--bws is required because $BWS_TARGET is not installed"
  fi

  sudoers_tmp="$(mktemp)"
  trap 'rm -f "${sudoers_tmp:-}"' EXIT
  install -o root -g root -m 0440 "$sudoers_source" "$sudoers_tmp"
  visudo -cf "$sudoers_tmp" >/dev/null

  nologin_shell="$(command -v nologin)" || fail "nologin shell not found"

  ensure_group "$WORKER_USER"
  ensure_group "$RUNNER_USER"
  ensure_group "$CLIENT_GROUP"
  ensure_service_account "$WORKER_USER" "$WORKER_HOME" "$nologin_shell"
  ensure_service_account "$RUNNER_USER" "$RUNNER_HOME" "$nologin_shell"

  usermod -a -G "$CLIENT_GROUP" "$client_user"
  account_fields "$client_user"
  client_home="$ACCOUNT_HOME"

  install -d -o "$WORKER_USER" -g "$WORKER_USER" -m 0700 "$WORKER_HOME"
  install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0700 "$RUNNER_HOME"
  install -d -o root -g root -m 0755 /etc/secrets-broker
  install -d -o "$WORKER_USER" -g "$WORKER_USER" -m 0700 "$AUDIT_DIR"

  install -D -o root -g root -m 0755 "$cli_source" "$CLI_TARGET"
  install -D -o root -g root -m 0755 "$worker_source" "$WORKER_TARGET"
  if [[ -n "$bws_source" ]]; then
    install -D -o root -g root -m 0755 "$bws_source" "$BWS_TARGET"
  else
    chown root:root "$BWS_TARGET"
    chmod 0755 "$BWS_TARGET"
  fi

  if [[ ! -e "$POLICY_TARGET" && ! -L "$POLICY_TARGET" ]]; then
    install -o root -g "$WORKER_USER" -m 0640 "$policy_source" "$POLICY_TARGET"
    note "Installed initial policy at $POLICY_TARGET."
  else
    chown root:"$WORKER_USER" "$POLICY_TARGET"
    chmod 0640 "$POLICY_TARGET"
    note "Preserved existing policy at $POLICY_TARGET."
  fi

  install -o root -g root -m 0440 "$sudoers_tmp" "$SUDOERS_TARGET"
  visudo -cf "$SUDOERS_TARGET" >/dev/null
  install -o root -g root -m 0644 "$logrotate_source" "$LOGROTATE_TARGET"
  logrotate --debug "$LOGROTATE_TARGET" >/dev/null 2>&1 || fail "installed logrotate policy is invalid"
  setfacl -m "u:$WORKER_USER:--x,u:$RUNNER_USER:--x" "$client_home"

  note "Worker deployment installed."
  note "Next: edit $POLICY_TARGET as root, then provision $TOKEN_FILE from a trusted terminal."
  note "Log out and back in before using the new $CLIENT_GROUP membership."
  note "Finish with: sudo $script_dir/install-worker.sh check --client-user $client_user"
  rm -f "$sudoers_tmp"
  trap - EXIT
}

check_worker() {
  local nologin_shell
  local client_home
  local token_size
  local cli_version
  local bws_version
  local sudo_version
  local worker_check

  for command_name in getent stat visudo getfacl grep cmp runuser sudo logrotate cut; do
    require_command "$command_name"
  done

  nologin_shell="$(command -v nologin)" || fail "nologin shell not found"
  check_service_account "$WORKER_USER" "$WORKER_HOME" "$nologin_shell"
  check_service_account "$RUNNER_USER" "$RUNNER_HOME" "$nologin_shell"
  getent group "$CLIENT_GROUP" >/dev/null || fail "group does not exist: $CLIENT_GROUP"

  account_fields "$client_user"
  client_home="$ACCOUNT_HOME"
  id -nG "$client_user" | tr ' ' '\n' | grep -Fxq "$CLIENT_GROUP" ||
    fail "$client_user is not a member of $CLIENT_GROUP"

  check_directory "$WORKER_HOME" "$WORKER_USER" "$WORKER_USER" 700
  check_directory "$RUNNER_HOME" "$RUNNER_USER" "$RUNNER_USER" 700
  check_directory /etc/secrets-broker root root 755
  check_directory "$AUDIT_DIR" "$WORKER_USER" "$WORKER_USER" 700
  check_regular_file "$CLI_TARGET" root root 755
  check_regular_file "$WORKER_TARGET" root root 755
  check_regular_file "$BWS_TARGET" root root 755
  check_regular_file "$POLICY_TARGET" root "$WORKER_USER" 640
  check_regular_file "$SUDOERS_TARGET" root root 440
  check_regular_file "$LOGROTATE_TARGET" root root 644
  [[ -f "$TOKEN_FILE" && ! -L "$TOKEN_FILE" ]] || fail "expected a regular, non-symlink file: $TOKEN_FILE"
  [[ "$(stat -c %U "$TOKEN_FILE")" == "$WORKER_USER" ]] || fail "$TOKEN_FILE has unexpected owner"
  [[ "$(stat -c %G "$TOKEN_FILE")" == "$WORKER_USER" ]] || fail "$TOKEN_FILE has unexpected group"
  [[ "$(stat -c %a "$TOKEN_FILE")" == 600 || "$(stat -c %a "$TOKEN_FILE")" == 400 ]] ||
    fail "$TOKEN_FILE must have mode 600 or 400"

  token_size="$(stat -c %s "$TOKEN_FILE")"
  (( token_size > 0 && token_size <= 65536 )) || fail "$TOKEN_FILE must be non-empty and no larger than 65536 bytes"
  if [[ -e "$AUDIT_FILE" || -L "$AUDIT_FILE" ]]; then
    check_regular_file "$AUDIT_FILE" "$WORKER_USER" "$WORKER_USER" 600
  fi

  ! grep -Eq 'PASTE-|YOUR-' "$POLICY_TARGET" || fail "$POLICY_TARGET still contains template placeholders"
  cmp -s "$SUDOERS_TARGET" "$sudoers_source" || fail "$SUDOERS_TARGET differs from the bundled policy"
  cmp -s "$LOGROTATE_TARGET" "$logrotate_source" || fail "$LOGROTATE_TARGET differs from the bundled policy"
  visudo -cf "$SUDOERS_TARGET" >/dev/null
  logrotate --debug "$LOGROTATE_TARGET" >/dev/null 2>&1 || fail "$LOGROTATE_TARGET is invalid"
  getfacl -cp "$client_home" | grep -Fxq "user:$WORKER_USER:--x" ||
    fail "$client_home does not grant traverse access to $WORKER_USER"
  getfacl -cp "$client_home" | grep -Fxq "user:$RUNNER_USER:--x" ||
    fail "$client_home does not grant traverse access to $RUNNER_USER"

  worker_check="$(runuser -u "$WORKER_USER" -- "$WORKER_TARGET" check 2>&1)" ||
    fail "worker semantic check failed: $worker_check"
  cli_version="$(runuser -u "$client_user" -- "$CLI_TARGET" version 2>&1)" || fail "CLI version check failed"
  bws_version="$(runuser -u "$RUNNER_USER" -- "$BWS_TARGET" --version 2>&1)" || fail "bws version check failed"
  sudo_version="$(sudo --version 2>&1 | sed -n '1p')"

  note "Worker check passed."
  note "$worker_check"
  note "CLI: ${cli_version%%$'\n'*}"
  note "bws: ${bws_version%%$'\n'*}"
  note "sudo: $sudo_version"
  note "Token metadata: owner and mode valid, $token_size bytes."
  note "Audit rotation: daily, 10 MiB threshold, 30 retained rotations."
}

case "$mode" in
  install)
    require_root
    parse_args "$@"
    install_worker
    ;;
  check)
    require_root
    parse_args "$@"
    check_worker
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

#!/usr/bin/env bash

set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
export LC_ALL=C
umask 077

readonly REPOSITORY=R055LE/secrets-broker
readonly SIGNER_WORKFLOW=R055LE/secrets-broker/.github/workflows/ci.yml
readonly SUDO=/usr/bin/sudo

usage() {
  cat <<'EOF'
Usage:
  secrets-broker-upgrade worker VERSION [--client-user USER]
  secrets-broker-upgrade relay VERSION

VERSION must be an explicit vMAJOR.MINOR.PATCH release, optionally with a
prerelease suffix. The helper downloads and verifies the matching release as
the current user, then uses sudo only for the root-owned staging, installer,
and check phase.

This command upgrades an existing deployment. It does not perform first-time
policy, token, relay-address, or Tailscale ACL setup.
EOF
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '%s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_regular_file() {
  local path="$1"
  local label="$2"

  [[ -f "$path" && ! -L "$path" ]] || fail "$label must be a regular, non-symlink file: $path"
}

release_dir=""
cleanup() {
  if [[ -n "$release_dir" && -d "$release_dir" && ! -L "$release_dir" ]]; then
    rm -rf -- "$release_dir"
  fi
}
trap cleanup EXIT

perform_verified_install() {
  (($# == 7)) || fail "invalid privileged upgrade request"
  (( EUID == 0 )) || fail "privileged upgrade phase must run as root"

  local install_role="$1"
  local install_version="$2"
  local install_arch="$3"
  local source_archive="$4"
  local expected_digest="$5"
  local install_client_user="$6"
  local caller_uid="$7"
  local install_bundle
  local install_archive
  local source_dir
  local source_mode
  local copied_archive
  local copied_digest
  local bundle_dir
  local installer

  [[ "$install_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
    fail "invalid privileged release version"
  [[ "$install_arch" == amd64 || "$install_arch" == arm64 ]] ||
    fail "invalid privileged release architecture"
  [[ "$expected_digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid privileged archive digest"
  [[ "$caller_uid" =~ ^[0-9]+$ && "$caller_uid" != 0 ]] || fail "invalid privileged caller UID"

  case "$install_role" in
    worker)
      [[ -n "$install_client_user" && "$install_client_user" != - ]] ||
        fail "privileged worker upgrade requires a client user"
      getent passwd "$install_client_user" >/dev/null ||
        fail "client account does not exist: $install_client_user"
      ;;
    relay)
      [[ "$install_client_user" == - ]] || fail "privileged relay upgrade received a client user"
      ;;
    *)
      fail "invalid privileged release role"
      ;;
  esac

  for command_name in sha256sum tar mktemp awk cmp stat cp rm getent; do
    require_command "$command_name"
  done

  install_bundle="secrets-broker-$install_version-linux-$install_arch"
  install_archive="$install_bundle.tar.gz"
  [[ "${source_archive##*/}" == "$install_archive" ]] || fail "privileged archive name does not match the release"
  require_regular_file "$source_archive" "operator-owned release archive"
  source_dir="${source_archive%/*}"
  [[ "$source_dir" == /tmp/secrets-broker-upgrade.* ]] || fail "release archive is outside the private upgrade directory"
  [[ -d "$source_dir" && ! -L "$source_dir" ]] || fail "upgrade directory is missing or unsafe"
  [[ "$(stat -c %u "$source_dir")" == "$caller_uid" ]] || fail "upgrade directory has an unexpected owner"
  [[ "$(stat -c %a "$source_dir")" == 700 ]] || fail "upgrade directory must have mode 700"
  [[ "$(stat -c %u "$source_archive")" == "$caller_uid" ]] || fail "release archive has an unexpected owner"
  source_mode="$(stat -c %a "$source_archive")"
  (( (8#$source_mode & 0022) == 0 )) || fail "release archive must not be group- or other-writable"

  release_dir="$(mktemp -d /var/tmp/secrets-broker-upgrade.XXXXXX)"
  copied_archive="$release_dir/$install_archive"
  cp --no-dereference -- "$source_archive" "$copied_archive"
  require_regular_file "$copied_archive" "root-owned release archive"
  [[ "$(stat -c %u "$copied_archive")" == 0 ]] || fail "copied release archive is not root-owned"
  copied_digest="$(sha256sum "$copied_archive" | awk '{print $1}')"
  [[ "$copied_digest" == "$expected_digest" ]] || fail "release archive changed before the privileged handoff"

  tar -xzf "$copied_archive" -C "$release_dir"
  bundle_dir="$release_dir/$install_bundle"
  [[ -d "$bundle_dir" && ! -L "$bundle_dir" ]] || fail "release bundle root is missing or unsafe"
  require_regular_file "$bundle_dir/deploy/upgrade-release.sh" "bundled upgrade helper"
  [[ -x "$bundle_dir/deploy/upgrade-release.sh" ]] || fail "bundled upgrade helper is not executable"

  case "$install_role" in
    worker)
      installer="$bundle_dir/deploy/install-worker.sh"
      require_regular_file "$installer" "worker installer"
      [[ -x "$installer" ]] || fail "worker installer is not executable"

      "$installer" install --client-user "$install_client_user"
      "$installer" check --client-user "$install_client_user"

      cmp -s "$bundle_dir/bin/secrets-broker" /usr/local/bin/secrets-broker ||
        fail "installed CLI does not match the verified release"
      cmp -s "$bundle_dir/bin/secrets-broker-admin" /usr/local/sbin/secrets-broker-admin ||
        fail "installed administrator CLI does not match the verified release"
      cmp -s "$bundle_dir/bin/secrets-broker-worker" /usr/local/libexec/secrets-broker-worker ||
        fail "installed worker does not match the verified release"
      cmp -s "$bundle_dir/deploy/upgrade-release.sh" /usr/local/bin/secrets-broker-upgrade ||
        fail "installed upgrade helper does not match the verified release"
      [[ "$(/usr/local/bin/secrets-broker version)" == "$install_version" ]] ||
        fail "installed CLI did not report $install_version"
      ;;
    relay)
      installer="$bundle_dir/deploy/install-relay.sh"
      require_regular_file "$installer" "relay installer"
      [[ -x "$installer" ]] || fail "relay installer is not executable"

      "$installer" install
      "$installer" check

      cmp -s "$bundle_dir/bin/secrets-broker-relay" /usr/local/bin/secrets-broker-relay ||
        fail "installed relay does not match the verified release"
      cmp -s "$bundle_dir/deploy/upgrade-release.sh" /usr/local/bin/secrets-broker-upgrade ||
        fail "installed upgrade helper does not match the verified release"
      ;;
  esac

  note "Secrets Broker $install_version $install_role upgrade passed."
}

if (($# == 1)); then
  case "$1" in
    -h|--help|help)
      usage
      exit 0
      ;;
  esac
fi

if [[ "${1:-}" == __install-verified ]]; then
  shift
  perform_verified_install "$@"
  exit 0
fi

(( EUID != 0 )) || fail "run this command as the unprivileged operator, without sudo"

if (($# < 2)); then
  usage >&2
  exit 2
fi

role="$1"
version="$2"
shift 2

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
  fail "version must use vMAJOR.MINOR.PATCH with an optional prerelease suffix"

client_user="$(id -un)"
case "$role" in
  worker)
    while (($#)); do
      case "$1" in
        --client-user)
          (($# >= 2)) || fail "--client-user requires a value"
          client_user="$2"
          shift 2
          ;;
        -h|--help)
          usage
          exit 0
          ;;
        *)
          fail "unknown worker option: $1"
          ;;
      esac
    done
    getent passwd "$client_user" >/dev/null || fail "client account does not exist: $client_user"
    [[ -x /usr/local/bin/secrets-broker && ! -L /usr/local/bin/secrets-broker ]] ||
      fail "worker role is not installed; use the first-install procedure"
    ;;
  relay)
    (($# == 0)) || fail "relay upgrade does not accept additional arguments"
    [[ -f /etc/secrets-broker-relay/environment && ! -L /etc/secrets-broker-relay/environment ]] ||
      fail "relay role is not installed; use the first-install procedure"
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    fail "role must be worker or relay"
    ;;
esac

for command_name in gh sha256sum mktemp awk grep id getent uname rm stat; do
  require_command "$command_name"
done
[[ -x "$SUDO" ]] || fail "required command not found: $SUDO"
require_regular_file /usr/local/bin/secrets-broker-upgrade "installed upgrade helper"
[[ -x /usr/local/bin/secrets-broker-upgrade ]] || fail "installed upgrade helper is not executable"
[[ "$(stat -c '%U:%G:%a' /usr/local/bin/secrets-broker-upgrade)" == root:root:755 ]] ||
  fail "installed upgrade helper must be root:root mode 755"

case "$(uname -m)" in
  x86_64)
    arch=amd64
    ;;
  aarch64|arm64)
    arch=arm64
    ;;
  *)
    fail "unsupported architecture: $(uname -m)"
    ;;
esac

bundle="secrets-broker-$version-linux-$arch"
archive="$bundle.tar.gz"
release_dir="$(mktemp -d /tmp/secrets-broker-upgrade.XXXXXX)"

note "Downloading $REPOSITORY $version for linux/$arch."
gh release download "$version" \
  --repo "$REPOSITORY" \
  --pattern checksums.txt \
  --pattern "$archive" \
  --dir "$release_dir"

require_regular_file "$release_dir/checksums.txt" "release checksums"
require_regular_file "$release_dir/$archive" "release archive"

if ! awk -v name="./$archive" '
  $2 == name { count++ }
  END { exit count == 1 ? 0 : 1 }
' "$release_dir/checksums.txt"; then
  fail "checksums.txt must contain exactly one entry for ./$archive"
fi

checksum_output=""
if ! checksum_output="$(
  cd -- "$release_dir"
  sha256sum --check --ignore-missing checksums.txt
)"; then
  [[ -z "$checksum_output" ]] || printf '%s\n' "$checksum_output" >&2
  fail "release checksum verification failed"
fi
printf '%s\n' "$checksum_output"
grep -Fxq "./$archive: OK" <<<"$checksum_output" ||
  fail "checksum verification did not confirm ./$archive"

archive_digest_before="$(sha256sum "$release_dir/$archive" | awk '{print $1}')"
attestation_count=""
if ! attestation_count="$(
  cd -- "$release_dir"
  gh attestation verify "$archive" \
    --repo "$REPOSITORY" \
    --signer-workflow "$SIGNER_WORKFLOW" \
    --source-ref "refs/tags/$version" \
    --deny-self-hosted-runners \
    --format json \
    --jq length
)"; then
  fail "release provenance verification failed"
fi
[[ "$attestation_count" == 1 ]] ||
  fail "expected exactly one matching provenance attestation, got $attestation_count"
note "Matching provenance attestations: $attestation_count"

archive_digest_after="$(sha256sum "$release_dir/$archive" | awk '{print $1}')"
[[ "$archive_digest_before" == "$archive_digest_after" ]] ||
  fail "release archive changed during provenance verification"

privileged_client_user=-
if [[ "$role" == worker ]]; then
  privileged_client_user="$client_user"
fi
note "Verified $version. Handing the bound archive to the root-owned $role installer."
"$SUDO" /usr/local/bin/secrets-broker-upgrade __install-verified \
  "$role" \
  "$version" \
  "$arch" \
  "$release_dir/$archive" \
  "$archive_digest_after" \
  "$privileged_client_user" \
  "$(id -u)"

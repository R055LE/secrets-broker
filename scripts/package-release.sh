#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
dist_dir="$repo_root/dist"
cd -- "$repo_root"

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

if (($# != 1)); then
  fail "usage: scripts/package-release.sh VERSION"
fi

version="$1"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
  fail "version must use vMAJOR.MINOR.PATCH with an optional prerelease suffix"

for command_name in go install sha256sum tar; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

if [[ -e "$dist_dir" || -L "$dist_dir" ]]; then
  [[ -d "$dist_dir" && ! -L "$dist_dir" ]] || fail "refusing unsafe dist path: $dist_dir"
  rm -rf -- "$dist_dir"
fi
install -d -m 0755 "$dist_dir"

for arch in amd64 arm64; do
  bundle="secrets-broker-$version-linux-$arch"
  stage_dir="$dist_dir/$bundle"

  install -d -m 0755 "$stage_dir" "$stage_dir/bin" "$stage_dir/deploy"

  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X github.com/R055LE/secrets-broker/internal/cli.Version=$version" \
    -o "$stage_dir/bin/secrets-broker" ./cmd/secrets-broker
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$stage_dir/bin/secrets-broker-worker" ./cmd/secrets-broker-worker
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$stage_dir/bin/secrets-broker-admin" ./cmd/secrets-broker-admin
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$stage_dir/bin/secrets-broker-relay" ./cmd/secrets-broker-relay
  chmod 0755 "$stage_dir/bin/secrets-broker" \
    "$stage_dir/bin/secrets-broker-admin" \
    "$stage_dir/bin/secrets-broker-worker" \
    "$stage_dir/bin/secrets-broker-relay"

  install -m 0755 deploy/install-worker.sh deploy/install-relay.sh "$stage_dir/deploy/"
  install -m 0644 \
    deploy/secrets-broker-relay.env.example \
    deploy/secrets-broker-relay.service \
    deploy/secrets-broker.logrotate \
    deploy/secrets-broker.sudoers \
    "$stage_dir/deploy/"
  install -m 0644 policy.example.toml README.md LICENSE "$stage_dir/"

  tar \
    --sort=name \
    --mtime='UTC 1970-01-01' \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -czf "$dist_dir/$bundle.tar.gz" \
    -C "$dist_dir" \
    "$bundle"
  rm -rf -- "$stage_dir"
done

(
  cd -- "$dist_dir"
  sha256sum -- ./*.tar.gz > checksums.txt
  sha256sum --check checksums.txt
)

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_PREFIX="[supply-chain-tools]"

log() {
  printf '%s %s\n' "$LOG_PREFIX" "$1"
}

run_with_privilege() {
  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo "$@"
  else
    "$@"
  fi
}

ensure_usr_local_bin() {
  if [ -d /usr/local/bin ]; then
    return
  fi
  run_with_privilege mkdir -p /usr/local/bin
}

install_trivy() {
  if command -v trivy >/dev/null 2>&1; then
    log "Trivy already present"
    return
  fi

  local version="0.50.2"
  local arch
  arch=$(uname -m)
  local archive_suffix
  case "$arch" in
    x86_64|amd64)
      archive_suffix="Linux-64bit"
      ;;
    aarch64|arm64)
      archive_suffix="Linux-ARM64"
      ;;
    armv7l|armv7)
      archive_suffix="Linux-ARM"
      ;;
    *)
      log "Unsupported architecture for Trivy ($arch); skipping"
      return
      ;;
  esac

  local tmp
  tmp=$(mktemp -d)
  local archive="trivy_${version}_${archive_suffix}.tar.gz"
  local url="https://github.com/aquasecurity/trivy/releases/download/v${version}/${archive}"
  curl -fsSL "$url" -o "$tmp/${archive}"
  tar -xzf "$tmp/${archive}" -C "$tmp" trivy
  ensure_usr_local_bin
  run_with_privilege install -m 755 "$tmp/trivy" /usr/local/bin/trivy
  rm -rf "$tmp"
}

install_grype() {
  if command -v grype >/dev/null 2>&1; then
    log "Grype already present"
    return
  fi

  local version="0.100.0"
  local arch
  arch=$(uname -m)
  local suffix
  case "$arch" in
    x86_64|amd64)
      suffix="linux_amd64"
      ;;
    aarch64|arm64)
      suffix="linux_arm64"
      ;;
    *)
      log "Unsupported architecture for Grype ($arch); skipping"
      return
      ;;
  esac

  local tmp
  tmp=$(mktemp -d)
  local archive="grype_${version}_${suffix}.tar.gz"
  local url="https://github.com/anchore/grype/releases/download/v${version}/${archive}"
  curl -fsSL "$url" -o "$tmp/${archive}"
  tar -xzf "$tmp/${archive}" -C "$tmp" grype
  ensure_usr_local_bin
  run_with_privilege install -m 755 "$tmp/grype" /usr/local/bin/grype
  rm -rf "$tmp"
}

install_syft() {
  if command -v syft >/dev/null 2>&1; then
    log "Syft already present"
    return
  fi

  local version="1.33.0"
  local arch
  arch=$(uname -m)
  local suffix
  case "$arch" in
    x86_64|amd64)
      suffix="linux_amd64"
      ;;
    aarch64|arm64)
      suffix="linux_arm64"
      ;;
    *)
      log "Unsupported architecture for Syft ($arch); skipping"
      return
      ;;
  esac

  local tmp
  tmp=$(mktemp -d)
  local archive="syft_${version}_${suffix}.tar.gz"
  local url="https://github.com/anchore/syft/releases/download/v${version}/${archive}"
  curl -fsSL "$url" -o "$tmp/${archive}"
  tar -xzf "$tmp/${archive}" -C "$tmp" syft
  ensure_usr_local_bin
  run_with_privilege install -m 755 "$tmp/syft" /usr/local/bin/syft
  rm -rf "$tmp"
}

install_cosign() {
  if command -v cosign >/dev/null 2>&1; then
    log "Cosign already present"
    return
  fi

  local version="2.6.0"
  local arch
  arch=$(uname -m)
  local suffix
  case "$arch" in
    x86_64|amd64)
      suffix="linux-amd64"
      ;;
    aarch64|arm64)
      suffix="linux-arm64"
      ;;
    *)
      log "Unsupported architecture for Cosign ($arch); skipping"
      return
      ;;
  esac

  local tmp
  tmp=$(mktemp -d)
  local url="https://github.com/sigstore/cosign/releases/download/v${version}/cosign-${suffix}"
  curl -fsSL "$url" -o "$tmp/cosign"
  chmod +x "$tmp/cosign"
  ensure_usr_local_bin
  run_with_privilege install -m 755 "$tmp/cosign" /usr/local/bin/cosign
  rm -rf "$tmp"
}

main() {
  install_trivy
  install_grype
  install_syft
  install_cosign
}

main "$@"

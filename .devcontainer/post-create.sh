#!/usr/bin/env bash
set -euo pipefail

APT_UPDATED=false

log() {
  printf '[post-create] %s\n' "$1"
}

ensure_command() {
  local cmd="$1"
  local pkg="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    return
  fi

  log "Installing dependency: $pkg"

  if [ "$APT_UPDATED" = false ]; then
    if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
      sudo apt-get update -y >/dev/null
    else
      apt-get update -y >/dev/null
    fi
    APT_UPDATED=true
  fi

  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo apt-get install -y "$pkg" >/dev/null
  else
    apt-get install -y "$pkg" >/dev/null
  fi
}

install_pnpm() {
  if command -v pnpm >/dev/null 2>&1; then
    log "pnpm already installed"
    return
  fi

  log "Installing pnpm@9 globally"
  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo npm install -g pnpm@9 >/dev/null
  else
    npm install -g pnpm@9 >/dev/null
  fi
}

install_semgrep() {
  if command -v semgrep >/dev/null 2>&1; then
    log "Semgrep already installed"
    return
  fi

  log "Installing Semgrep"

  ensure_command python3 python3
  ensure_command pip3 python3-pip

  local pip_args=(--upgrade --no-cache-dir)
  if python3 -m pip help install 2>/dev/null | grep -q -- '--break-system-packages'; then
    pip_args+=(--break-system-packages)
  fi

  pip_args+=(semgrep)

  local install_cmd=(python3 -m pip install "${pip_args[@]}")
  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo "${install_cmd[@]}" >/dev/null
  else
    "${install_cmd[@]}" >/dev/null
  fi
}

install_gitleaks() {
  if command -v gitleaks >/dev/null 2>&1; then
    log "Gitleaks already installed"
    return
  fi

  log "Installing Gitleaks"
  local version="8.28.0"
  local arch
  arch=$(uname -m)

  local asset_suffix=""
  case "$arch" in
    x86_64|amd64)
      asset_suffix="linux_x64"
      ;;
    aarch64|arm64)
      asset_suffix="linux_arm64"
      ;;
    armv7l)
      asset_suffix="linux_armv7"
      ;;
    armv6l)
      asset_suffix="linux_armv6"
      ;;
    i386|i686)
      asset_suffix="linux_x32"
      ;;
    *)
      log "Unsupported architecture for Gitleaks: $arch"
      return 1
      ;;
  esac

  local tmp_dir
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' EXIT

  local tarball="gitleaks_${version}_${asset_suffix}.tar.gz"
  local url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/${tarball}"

  ensure_command curl curl

  curl -sSL "$url" -o "$tmp_dir/$tarball"
  tar -xzf "$tmp_dir/$tarball" -C "$tmp_dir"

  if [ ! -d /usr/local/bin ]; then
    if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
      sudo mkdir -p /usr/local/bin
    else
      mkdir -p /usr/local/bin
    fi
  fi

  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo mv "$tmp_dir/gitleaks" /usr/local/bin/gitleaks
    sudo chmod +x /usr/local/bin/gitleaks
  else
    mv "$tmp_dir/gitleaks" /usr/local/bin/gitleaks
    chmod +x /usr/local/bin/gitleaks
  fi

  rm -rf "$tmp_dir"
  trap - EXIT
}

configure_git() {
  log "Configuring git safe directory"
  git config --global --add safe.directory /workspaces/*
}

main() {
  install_pnpm
  install_semgrep
  install_gitleaks
  configure_git
  log "Post-create configuration complete"
}

main

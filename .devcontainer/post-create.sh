#!/usr/bin/env bash
set -euo pipefail 2>/dev/null || set -eu

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

install_infisical_cli() {
  if command -v infisical >/dev/null 2>&1; then
    log "Infisical CLI already installed"
    return
  fi

  log "Installing Infisical CLI"
  ensure_command curl curl

  local install_cmd=(npm install -g infisical)
  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    if ! sudo "${install_cmd[@]}" >/dev/null; then
      log "npm installation of Infisical CLI failed"
      return 1
    fi
  else
    if ! "${install_cmd[@]}" >/dev/null; then
      log "npm installation of Infisical CLI failed"
      return 1
    fi
  fi

  if command -v infisical >/dev/null 2>&1; then
    log "Infisical CLI installation complete"
  else
    log "Infisical CLI installation attempted but command not found"
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

install_claude_code_cli() {
  if command -v claude >/dev/null 2>&1; then
    log "Claude Code CLI already installed"
    return
  fi

  log "Installing Claude Code CLI"

  local install_cmd=(npm install -g @anthropic-ai/claude-code)
  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo "${install_cmd[@]}" >/dev/null
  else
    "${install_cmd[@]}" >/dev/null
  fi
}

install_cursor_openai_codex_extension() {
  local publisher="openai"
  local name="chatgpt"
  local version="0.4.12"
  local extension_id="${publisher}.${name}"
  local vsix_url="https://open-vsx.org/api/${publisher}/${name}/${version}/file/${extension_id}-${version}.vsix"

  ensure_command curl curl
  ensure_command unzip unzip

  local remote_user="${DEVCONTAINER_REMOTE_USER:-${REMOTE_USER:-}}"
  local remote_home=""
  local remote_group=""
  if [ -n "$remote_user" ]; then
    if command -v getent >/dev/null 2>&1; then
      remote_home=$(getent passwd "$remote_user" 2>/dev/null | cut -d: -f6 || true)
    elif [ -f /etc/passwd ]; then
      remote_home=$(awk -F: -v u="$remote_user" '$1 == u { print $6 }')
    fi
    if command -v id >/dev/null 2>&1; then
      remote_group=$(id -gn "$remote_user" 2>/dev/null || true)
    fi
  fi

  local -a base_candidates=("$HOME")
  if [ -n "$remote_home" ]; then
    base_candidates+=("$remote_home")
  fi
  if [ -n "$remote_user" ] && [ -d "/home/$remote_user" ]; then
    base_candidates+=("/home/$remote_user")
  fi
  if [ -d "/home/node" ]; then
    base_candidates+=("/home/node")
  fi
  if [ -d "/home/codespace" ]; then
    base_candidates+=("/home/codespace")
  fi
  if [ -d "/root" ]; then
    base_candidates+=("/root")
  fi

  local -a base_dirs=()
  local candidate
  for candidate in "${base_candidates[@]}"; do
    [ -z "$candidate" ] && continue
    if [ ! -d "$candidate" ]; then
      continue
    fi
    case " ${base_dirs[*]} " in
      *" $candidate "*)
        continue
        ;;
    esac
    base_dirs+=("$candidate")
  done

  if [ "${#base_dirs[@]}" -eq 0 ]; then
    base_dirs=("$HOME")
  fi

  local -a targets=()
  local base
  for base in "${base_dirs[@]}"; do
    [ -z "$base" ] && continue
    local cursor_root="${base}/.cursor-server/extensions"
    if ! mkdir -p "$cursor_root" 2>/dev/null; then
      log "Skipping Codex install target $cursor_root (insufficient permissions)"
      continue
    fi
    targets+=("$cursor_root/${extension_id}-${version}")
  done

  if [ "${#targets[@]}" -eq 0 ]; then
    log "No Cursor extension locations available for Codex install"
    return 0
  fi

  local needs_download=false
  local dest
  for dest in "${targets[@]}"; do
    if [ ! -f "$dest/package.json" ]; then
      needs_download=true
      break
    fi
  done

  if [ "$needs_download" = false ]; then
    log "OpenAI Codex extension already present in Cursor directories"
    return 0
  fi

  local tmp_dir
  tmp_dir=$(mktemp -d)
  if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
    log "Unable to create temp directory for Codex extension"
    return 0
  fi

  local vsix_path="$tmp_dir/${extension_id}-${version}.vsix"
  if ! curl -fsSL "$vsix_url" -o "$vsix_path"; then
    log "Failed to download OpenAI Codex extension from Open VSX"
    rm -rf "$tmp_dir"
    return 0
  fi

  local extracted_dir="$tmp_dir/extracted"
  mkdir -p "$extracted_dir"
  if ! unzip -q "$vsix_path" -d "$extracted_dir"; then
    log "Failed to unpack OpenAI Codex extension package"
    rm -rf "$tmp_dir"
    return 0
  fi

  local extension_source="$extracted_dir"
  if [ -d "$extracted_dir/extension" ]; then
    extension_source="$extracted_dir/extension"
  fi

  local installed_any=false
  for dest in "${targets[@]}"; do
    rm -rf "$dest" 2>/dev/null || true
    if ! mkdir -p "$dest" 2>/dev/null; then
      log "Failed to prepare Codex install location $dest"
      continue
    fi

    if cp -a "$extension_source/." "$dest/"; then
      installed_any=true
      if [ "$(id -u)" -eq 0 ]; then
        local owner
        local group
        owner=$(stat -c '%U' "${dest%/*}" 2>/dev/null || echo "")
        group=$(stat -c '%G' "${dest%/*}" 2>/dev/null || echo "")
        if [ -n "$owner" ] && [ "$owner" != "root" ]; then
          chown -R "$owner:${group:-$owner}" "$dest" 2>/dev/null || true
        elif [ -n "$remote_user" ] && [ -n "$remote_group" ] && [ -n "$remote_home" ] && [[ "$dest" == "$remote_home/"* ]]; then
          chown -R "$remote_user:$remote_group" "$dest" 2>/dev/null || true
        fi
      fi
      log "Installed OpenAI Codex extension v${version} in $dest"
    else
      log "Failed to copy OpenAI Codex extension into $dest"
      rm -rf "$dest" 2>/dev/null || true
    fi
  done

  rm -rf "$tmp_dir" 2>/dev/null || true

  if [ "$installed_any" = true ]; then
    log "OpenAI Codex extension installation complete"
  else
    log "Unable to install OpenAI Codex extension"
  fi
}


configure_git() {
  log "Configuring git safe directory"
  git config --global --add safe.directory /workspaces/*
}

main() {
  install_pnpm
  install_infisical_cli
  install_semgrep
  install_gitleaks
  install_claude_code_cli
  install_cursor_openai_codex_extension
  configure_git
  log "Post-create configuration complete"
}

main

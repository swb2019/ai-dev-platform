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

ensure_usr_local_bin() {
  if [ -d /usr/local/bin ]; then
    return
  fi

  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo mkdir -p /usr/local/bin
  else
    mkdir -p /usr/local/bin
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

  log "Installing Infisical CLI (@infisical/cli)"

  local package="@infisical/cli"
  local install_cmd=(npm install -g "$package")
  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    if ! sudo "${install_cmd[@]}" >/dev/null; then
      log "npm installation of Infisical CLI (@infisical/cli) failed"
      return 1
    fi
  else
    if ! "${install_cmd[@]}" >/dev/null; then
      log "npm installation of Infisical CLI (@infisical/cli) failed"
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

install_trivy() {
  if command -v trivy >/dev/null 2>&1; then
    log "Trivy already installed"
    return
  fi

  log "Installing Trivy"
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
      log "Unsupported architecture for Trivy: $arch"
      return 0
      ;;
  esac

  local tmp_dir
  tmp_dir=$(mktemp -d)
  if [ ! -d "$tmp_dir" ]; then
    log "Failed to create temporary directory for Trivy install"
    return 1
  fi

  local archive_name="trivy_${version}_${archive_suffix}.tar.gz"
  local url="https://github.com/aquasecurity/trivy/releases/download/v${version}/${archive_name}"

  if ! curl -fsSL "$url" -o "$tmp_dir/${archive_name}"; then
    log "Failed to download Trivy from $url"
    rm -rf "$tmp_dir" 2>/dev/null || true
    return 1
  fi

  if ! tar -xzf "$tmp_dir/${archive_name}" -C "$tmp_dir" trivy; then
    log "Failed to extract Trivy archive"
    rm -rf "$tmp_dir" 2>/dev/null || true
    return 1
  fi

  ensure_usr_local_bin

  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo install -m 755 "$tmp_dir/trivy" /usr/local/bin/trivy >/dev/null
  else
    install -m 755 "$tmp_dir/trivy" /usr/local/bin/trivy >/dev/null
  fi

  rm -rf "$tmp_dir" 2>/dev/null || true
}

install_grype() {
  if command -v grype >/dev/null 2>&1; then
    log "Grype already installed"
    return
  fi

  log "Installing Grype"
  local version="0.100.0"
  local arch
  arch=$(uname -m)
  local archive_suffix

  case "$arch" in
    x86_64|amd64)
      archive_suffix="linux_amd64"
      ;;
    aarch64|arm64)
      archive_suffix="linux_arm64"
      ;;
    *)
      log "Unsupported architecture for Grype: $arch"
      return 0
      ;;
  esac

  local tmp_dir
  tmp_dir=$(mktemp -d)
  if [ ! -d "$tmp_dir" ]; then
    log "Failed to create temporary directory for Grype install"
    return 1
  fi

  local archive_name="grype_${version}_${archive_suffix}.tar.gz"
  local url="https://github.com/anchore/grype/releases/download/v${version}/${archive_name}"

  if ! curl -fsSL "$url" -o "$tmp_dir/${archive_name}"; then
    log "Failed to download Grype from $url"
    rm -rf "$tmp_dir" 2>/dev/null || true
    return 1
  fi

  if ! tar -xzf "$tmp_dir/${archive_name}" -C "$tmp_dir" grype; then
    log "Failed to extract Grype archive"
    rm -rf "$tmp_dir" 2>/dev/null || true
    return 1
  fi

  ensure_usr_local_bin

  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo install -m 755 "$tmp_dir/grype" /usr/local/bin/grype >/dev/null
  else
    install -m 755 "$tmp_dir/grype" /usr/local/bin/grype >/dev/null
  fi

  rm -rf "$tmp_dir" 2>/dev/null || true
}

install_syft() {
  if command -v syft >/dev/null 2>&1; then
    log "Syft already installed"
    return
  fi

  log "Installing Syft"
  local version="1.33.0"
  local arch
  arch=$(uname -m)
  local archive_suffix

  case "$arch" in
    x86_64|amd64)
      archive_suffix="linux_amd64"
      ;;
    aarch64|arm64)
      archive_suffix="linux_arm64"
      ;;
    *)
      log "Unsupported architecture for Syft: $arch"
      return 0
      ;;
  esac

  local tmp_dir
  tmp_dir=$(mktemp -d)
  if [ ! -d "$tmp_dir" ]; then
    log "Failed to create temporary directory for Syft install"
    return 1
  fi

  local archive_name="syft_${version}_${archive_suffix}.tar.gz"
  local url="https://github.com/anchore/syft/releases/download/v${version}/${archive_name}"

  if ! curl -fsSL "$url" -o "$tmp_dir/${archive_name}"; then
    log "Failed to download Syft from $url"
    rm -rf "$tmp_dir" 2>/dev/null || true
    return 1
  fi

  if ! tar -xzf "$tmp_dir/${archive_name}" -C "$tmp_dir" syft; then
    log "Failed to extract Syft archive"
    rm -rf "$tmp_dir" 2>/dev/null || true
    return 1
  fi

  ensure_usr_local_bin

  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo install -m 755 "$tmp_dir/syft" /usr/local/bin/syft >/dev/null
  else
    install -m 755 "$tmp_dir/syft" /usr/local/bin/syft >/dev/null
  fi

  rm -rf "$tmp_dir" 2>/dev/null || true
}

install_cosign() {
  if command -v cosign >/dev/null 2>&1; then
    log "Cosign already installed"
    return
  fi

  log "Installing Cosign"
  local version="2.6.0"
  local arch
  arch=$(uname -m)
  local binary_suffix

  case "$arch" in
    x86_64|amd64)
      binary_suffix="linux-amd64"
      ;;
    aarch64|arm64)
      binary_suffix="linux-arm64"
      ;;
    *)
      log "Unsupported architecture for Cosign: $arch"
      return 0
      ;;
  esac

  local tmp_dir
  tmp_dir=$(mktemp -d)
  if [ ! -d "$tmp_dir" ]; then
    log "Failed to create temporary directory for Cosign install"
    return 1
  fi

  local url="https://github.com/sigstore/cosign/releases/download/v${version}/cosign-${binary_suffix}"
  local destination="$tmp_dir/cosign"

  if ! curl -fsSL "$url" -o "$destination"; then
    log "Failed to download Cosign from $url"
    rm -rf "$tmp_dir" 2>/dev/null || true
    return 1
  fi

  chmod +x "$destination"

  ensure_usr_local_bin

  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    sudo install -m 755 "$destination" /usr/local/bin/cosign >/dev/null
  else
    install -m 755 "$destination" /usr/local/bin/cosign >/dev/null
  fi

  rm -rf "$tmp_dir" 2>/dev/null || true
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
  if [ -d "/root" ] && [ "$(id -u)" -eq 0 ]; then
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

bootstrap_workspace_dependencies() {
  if [ ! -f package.json ]; then
    log "No package.json detected; skipping pnpm install"
    return
  fi

  if [ -d node_modules ]; then
    log "node_modules directory already present; skipping pnpm install"
    return
  fi

  if ! command -v pnpm >/dev/null 2>&1; then
    log "pnpm not available; cannot install workspace dependencies"
    return
  fi

  log "Installing workspace dependencies (pnpm install)"
  if ! pnpm install --frozen-lockfile --reporter=silent; then
    log "pnpm install with frozen lockfile failed; retrying without --frozen-lockfile"
    pnpm install --reporter=default
  fi
}

initialize_husky() {
  if [ ! -d .husky ]; then
    log "No .husky directory detected; skipping Husky initialization"
    return
  fi

  if ! command -v pnpm >/dev/null 2>&1; then
    log "pnpm not available; cannot initialize Husky"
    return
  fi

  log "Initializing Husky git hooks"
  if ! pnpm exec husky >/dev/null 2>&1; then
    log "Husky initialization failed. Run 'pnpm install' and retry manually."
  fi
}

main() {
  install_pnpm
  install_infisical_cli
  install_semgrep
  install_gitleaks
  install_trivy
  install_grype
  install_syft
  install_cosign
  install_claude_code_cli
  install_cursor_openai_codex_extension
  configure_git
  bootstrap_workspace_dependencies
  initialize_husky
  log "Post-create configuration complete"
}

main

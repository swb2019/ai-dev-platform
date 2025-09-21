#!/bin/bash
set -e

# --- Helper Functions ---
# Function to run commands with sudo if available and needed (DevContainers usually have passwordless sudo)
run_cmd() {
    if [ "$(id -u)" != "0" ] && command -v sudo &> /dev/null; then
        sudo "$@"
    else
        "$@"
    fi
}

# --- Security Tools Installation ---
echo "Installing Security Tools..."

# 1. Ensure dependencies (pip, curl) are installed.
if ! command -v pip3 &> /dev/null || ! command -v curl &> /dev/null; then
    echo "Installing python3-pip and curl..."
    # Ensure the package list is updated before installation
    if ! apt-get update; then
        echo "Warning: apt-get update failed. Attempting to install dependencies anyway."
    fi
    run_cmd apt-get install -y python3-pip curl
fi

# 2. Install Semgrep (Install globally using pip with sudo if necessary)
echo "Installing Semgrep..."
if [ "$(id -u)" != "0" ] && command -v sudo &> /dev/null; then
    sudo pip3 install semgrep
else
    pip3 install semgrep
fi

# 3. Install Gitleaks (Architecture aware)
echo "Installing Gitleaks..."
GITLEAKS_VERSION="8.18.4" # Use the latest stable version
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    GITLEAKS_ARCH="x64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    GITLEAKS_ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" | tar xz

# Move to path
run_cmd mv gitleaks /usr/local/bin/
run_cmd chmod +x /usr/local/bin/gitleaks

# --- Git Configuration Override and Safety ---
echo "Enforcing Git configuration and safety for Linux environment..."
# Unset potentially conflicting credential helpers and ensure workspace safety.
# We apply settings globally for the primary user ('node' if it exists, otherwise the current user).

# Determine the primary user to configure
if id "node" &>/dev/null; then
    PRIMARY_USER="node"
else
    PRIMARY_USER=$(whoami)
fi

# Function to run configuration commands as the primary user
# Using 'sudo -u' as it is generally available in DevContainers
run_as_user() {
    # Check if we are already the primary user
    if [ "$(whoami)" = "$PRIMARY_USER" ]; then
        "$@"
    # Check if sudo is available and we are root/able to switch user
    elif command -v sudo &>/dev/null; then
        # Use sudo -u to run the command as the primary user. Use 'env' to preserve PATH.
        sudo -u "$PRIMARY_USER" env PATH="$PATH" "$@"
    else
        echo "Warning: Cannot switch to $PRIMARY_USER. Running as $(whoami)."
        "$@"
    fi
}

# Apply configurations
# Unset conflicting helpers (e.g., from Windows host)
run_as_user git config --global --unset-all credential.helper || true
# Mark workspace as safe to prevent dubious ownership errors
run_as_user git config --global --add safe.directory /workspaces/ai-dev-platform || true
# Ensure 'gh' is configured as the credential helper for the Linux environment
# This relies on 'gh auth login' having been completed previously and the token being available.
run_as_user gh auth setup-git || true

echo "Post-create command finished."
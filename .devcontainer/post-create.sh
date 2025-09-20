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
    run_cmd apt-get update
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

echo "Post-create command finished."
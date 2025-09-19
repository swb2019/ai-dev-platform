#!/bin/bash
set -e

echo "🚀 AI Dev Platform - Post-Create Setup"

# Install security tools
echo "📦 Installing security tools..."

# Install Semgrep via pip
pip3 install semgrep

# Install Gitleaks
GITLEAKS_VERSION="8.18.4"
curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /tmp
sudo mv /tmp/gitleaks /usr/local/bin/
chmod +x /usr/local/bin/gitleaks

# Install pnpm globally
npm install -g pnpm@9

# Verify installations
echo "🔍 Verifying installations..."
semgrep --version
gitleaks version
pnpm --version

# Install dependencies if package.json exists
if [ -f "package.json" ]; then
    echo "📦 Installing project dependencies..."
    pnpm install

    # Initialize Husky if it exists
    if [ -d "node_modules/.bin" ] && [ -x "node_modules/.bin/husky" ]; then
        echo "🐕 Initializing Husky..."
        pnpm exec husky install
    fi
fi

echo "✅ Setup complete!"
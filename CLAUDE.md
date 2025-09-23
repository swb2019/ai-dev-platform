# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the Gitleaks repository, a SAST (Static Application Security Testing) tool for detecting and preventing hardcoded secrets like passwords, API keys, and tokens in git repositories. Gitleaks is written in Go and provides both CLI and library functionality for secret detection.

## Development Environment

This project uses a DevContainer setup with the following key components:

- **Runtime**: Node.js 20 with TypeScript support
- **Security Tools**: Semgrep, Gitleaks, OpenAI CLI
- **AI Development**: Claude Code CLI, GitHub Copilot, ChatGPT extension
- **Code Quality**: ESLint, Prettier, VS Code IntelliCode

## Commands

Since this appears to be a Go-based tool (Gitleaks) but the DevContainer is set up for Node.js/TypeScript development, the available commands depend on the actual project structure. Based on the analysis:

**Post-setup commands** (run automatically via DevContainer):

```bash
# These are handled by .devcontainer/post-create.sh
npm install -g @anthropic-ai/claude-code
npm install -g typescript ts-node nodemon
pip3 install semgrep openai
```

**Security scanning commands** (using installed tools):

```bash
# Run Gitleaks to detect secrets
gitleaks detect --source . -v

# Run Semgrep for additional security analysis
semgrep --config=auto .
```

**Development commands** (if TypeScript/Node.js project):

```bash
# Common development commands would be:
npm run build    # Build the project
npm run test     # Run tests
npm run lint     # Run linting
npm run dev      # Start development server
```

## Architecture

This repository is configured as an AI development platform with:

1. **DevContainer Environment**: Provides a consistent development environment with pre-installed AI and security tools
2. **Multi-AI Support**: Configured for Claude Code, GitHub Copilot, and ChatGPT integration
3. **Security-First Approach**: Includes Gitleaks and Semgrep for automated security scanning
4. **TypeScript/Node.js Stack**: Primary development environment despite being a Gitleaks repository

The DevContainer automatically installs and configures:

- Security scanning tools (Gitleaks v8.18.4, Semgrep)
- AI development tools (Claude Code CLI, OpenAI CLI)
- Development utilities (TypeScript, ts-node, nodemon)

## VS Code Configuration

The project includes comprehensive VS Code settings for:

- Auto-formatting with Prettier on save
- ESLint integration with auto-fix
- TypeScript support with advanced IntelliSense
- Multi-AI assistant integration (Claude, Copilot, ChatGPT)
- Optimized editor settings for AI-assisted development

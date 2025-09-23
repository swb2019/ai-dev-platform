# AI Dev Platform

A secure, AI-powered development platform built with modern tools and security-first architecture.

## Features

- 🔒 **Security First**: Built-in security scanning with Gitleaks, Semgrep, and comprehensive linting
- 🤖 **AI-Powered**: Integrated AI development tools including Claude Code and GitHub Copilot
- 🏗️ **Modern Stack**: Next.js 14, TypeScript, Tailwind CSS, and Turbo monorepo architecture
- ⚡ **Performance**: Optimized build pipelines with caching and parallel execution
- 🧪 **Quality Assurance**: Comprehensive testing with Jest and React Testing Library
- 📦 **Monorepo**: Organized workspace with shared configurations and tools

## Quick Start

### Prerequisites

- Node.js 18+
- pnpm 8+
- Git

### Installation

1. Clone the repository:

```bash
git clone https://github.com/swb2019/ai-dev-platform.git
cd ai-dev-platform
```

2. Install dependencies:

```bash
pnpm install
```

3. Start development server:

```bash
pnpm dev
```

## Project Structure

```
ai-dev-platform/
├── apps/
│   └── web/                 # Next.js web application
├── packages/
│   ├── tsconfig/           # Shared TypeScript configurations
│   └── eslint-config-custom/ # Shared ESLint configurations
├── tools/                  # Development tools and utilities
├── docs/                   # Documentation
└── .github/workflows/      # CI/CD pipelines
```

## Development

### Available Scripts

- `pnpm dev` - Start development servers
- `pnpm build` - Build all applications
- `pnpm test` - Run all tests
- `pnpm lint` - Lint all code
- `pnpm type-check` - Type check all TypeScript code
- `pnpm format` - Format code with Prettier
- `pnpm docker:build:web` - Build the production container image for the web app
- `pnpm docker:scan:web` - Run Trivy and Grype vulnerability scans on the image
- `pnpm docker:sbom:web` - Generate a CycloneDX SBOM for the image
- `pnpm docker:sign:sbom` - Keyless-sign the generated SBOM with Cosign

### Development Workflow

1. Create a feature branch: `git checkout -b feat/your-feature`
2. Make your changes
3. Ensure all checks pass: `pnpm lint && pnpm type-check && pnpm test`
4. Commit your changes following conventional commits
5. Push and create a pull request

### Security

This project includes multiple security layers:

- **Pre-commit hooks**: Automated security scanning and linting
- **CI/CD pipeline**: Comprehensive security checks on all PRs
- **Dependency scanning**: Automated vulnerability detection
- **Code analysis**: Static analysis with Semgrep and ESLint security rules

## Architecture

### Monorepo Structure

The project uses a monorepo architecture with:

- **Apps**: Individual applications (web, mobile, desktop)
- **Packages**: Shared libraries and configurations
- **Tools**: Development utilities and scripts

### Shared Configurations

- **TypeScript**: Strict type checking with multiple configuration presets
- **ESLint**: Security-focused linting with comprehensive rule sets
- **Prettier**: Consistent code formatting
- **Jest**: Testing framework with React Testing Library

### CI/CD Pipeline

Automated workflows include:

1. **Security Scans**: Gitleaks and Semgrep analysis
2. **Quality Checks**: Linting, type checking, and formatting
3. **Testing**: Unit and integration tests with coverage reporting
4. **Build**: Production builds with optimization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the development workflow
4. Ensure all security checks pass
5. Submit a pull request

### Code Standards

- Use TypeScript for all new code
- Follow the established ESLint configuration
- Write tests for new functionality
- Maintain 80%+ test coverage
- Follow security best practices

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Documentation

- [Agent Protocols](docs/AGENT_PROTOCOLS.md) - Autonomous development protocols
- [Architecture Guide](docs/ARCHITECTURE.md) - Detailed system architecture
- [Security Guide](docs/SECURITY.md) - Security practices and guidelines
- [Supply Chain Guide](docs/SUPPLY_CHAIN.md) - Containerization, scanning, SBOMs, and signing workflows

## Support

For questions or support, please:

1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information

---

Built with ❤️ using modern development practices and AI-powered tools.

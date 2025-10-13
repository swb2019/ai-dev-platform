# AI Dev Platform

**A secure, production-ready foundation for deploying AI-oriented applications to Google Kubernetes Engine (GKE) Autopilot.**

The AI Dev Platform is a comprehensive monorepo that bundles a modern Next.js 14 application, shared TypeScript tooling, Terraform-based infrastructure, and automated CI/CD pipelines. It is designed with a security-first approach, integrating supply-chain scanning, binary authorization, and end-to-end validation to ensure robust and reliable deployments.

## Key Features

- **Modern web stack:** Next.js 14 (App Router), React 18, and Tailwind CSS v4.
- **GKE Autopilot delivery:** Automated Kubernetes deployments via Kustomize and Gateway API routing.
- **Infrastructure as Code:** GCP infrastructure managed entirely by Terraform (GKE, networking, Workload Identity Federation, Artifact Registry).
- **Secure CI/CD:** GitHub Actions workflows authenticate to GCP via Workload Identity Federation for keyless operations.
- **Supply-chain security:** Integrated scanning (Trivy, Grype), SBOM generation (Syft), and keyless signing (Cosign).
- **Binary Authorization:** Enforced in GKE so only signed and attested images are admitted.
- **Comprehensive testing:** Jest + Testing Library unit tests and Playwright E2E tests wired into the delivery pipeline.
- **Monorepo ergonomics:** PNPM workspaces and Turbo coordinate builds, tests, and shared tooling.
- **Security guardrails:** Gitleaks, Semgrep, CodeQL, and centralized ESLint rules (security + SonarJS) run locally and in CI.

## Architecture Overview

This platform leverages GKE Autopilot for managed Kubernetes, using the Gateway API for external traffic management. Infrastructure is composed with Terraform modules and applied per environment (staging and production). Deployments rely on Kustomize overlays that inject immutable image digests and Workload Identity bindings. GitHub Actions authenticates through Workload Identity Federation (WIF) to push signed images to Artifact Registry and apply manifests to GKE, where Binary Authorization enforces attestation policies.

```svg
<svg width="800" height="450" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 450">
  <style>
    .container { fill: #f0f4f8; stroke: #d1d9e6; stroke-width: 2; rx: 10; }
    .component { fill: #ffffff; stroke: #a0aec0; stroke-width: 1; rx: 5; }
    .actor { fill: #ebf8ff; stroke: #4299e1; stroke-width: 2; rx: 5; }
    .ci-tool { fill: #e6fffa; stroke: #38b2ac; stroke-width: 1; rx: 5; }
    .text { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 14px; fill: #2d3748; }
    .title { font-size: 16px; font-weight: bold; }
    .arrow { stroke: #718096; stroke-width: 2; fill: none; marker-end: url(#arrowhead); }
    .dashed-arrow { stroke-dasharray: 5,5; }
  </style>
  <defs>
    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#718096" />
    </marker>
  </defs>

  <rect x="10" y="50" width="100" height="50" class="actor"/>
  <text x="60" y="80" class="text" text-anchor="middle">Developer</text>

  <rect x="690" y="200" width="100" height="50" class="actor"/>
  <text x="740" y="230" class="text" text-anchor="middle">End User</text>

  <rect x="150" y="10" width="500" height="130" class="container"/>
  <text x="160" y="30" class="title">CI/CD &amp; Infrastructure Management</text>

  <rect x="170" y="50" width="120" height="50" class="component"/>
  <text x="230" y="80" class="text" text-anchor="middle">GitHub Actions</text>

  <rect x="310" y="50" width="120" height="50" class="component"/>
  <text x="370" y="80" class="text" text-anchor="middle">Terraform</text>

  <rect x="460" y="50" width="150" height="50" class="ci-tool"/>
  <text x="535" y="70" class="text" text-anchor="middle">Workload Identity</text>
  <text x="535" y="90" class="text" text-anchor="middle">Federation (WIF)</text>

  <rect x="150" y="150" width="500" height="280" class="container"/>
  <text x="160" y="170" class="title">Google Cloud Platform (GCP)</text>

  <rect x="170" y="190" width="140" height="80" class="component"/>
  <text x="240" y="220" class="text" text-anchor="middle">Artifact Registry</text>
  <text x="240" y="245" class="text" text-anchor="middle">(Docker Images</text>
  <text x="240" y="260" class="text" text-anchor="middle">&amp; Attestations)</text>

  <rect x="340" y="190" width="290" height="220" class="container" style="fill: #e2e8f0;"/>
  <text x="350" y="210" class="title">GKE Autopilot Cluster</text>

  <rect x="360" y="230" width="120" height="50" class="component"/>
  <text x="420" y="260" class="text" text-anchor="middle">Gateway API</text>

  <rect x="500" y="230" width="110" height="50" class="component"/>
  <text x="555" y="250" class="text" text-anchor="middle">Binary</text>
  <text x="555" y="270" class="text" text-anchor="middle">Authorization</text>

  <rect x="360" y="300" width="120" height="50" class="component"/>
  <text x="420" y="330" class="text" text-anchor="middle">Next.js Pods</text>

  <rect x="500" y="300" width="110" height="50" class="ci-tool"/>
  <text x="555" y="320" class="text" text-anchor="middle">Workload</text>
  <text x="555" y="340" class="text" text-anchor="middle">Identity</text>

  <path d="M110,75 C 130,75 130,75 170,75" class="arrow"/>

  <path d="M300,100 C 300,115 460,115 460,100" class="arrow dashed-arrow"/>
  <text x="380" y="125" class="text" text-anchor="middle" font-size="12px">Authenticates</text>

  <path d="M430,90 C 430,120 400,120 400,150" class="arrow"/>
  <text x="430" y="135" class="text" text-anchor="middle" font-size="12px">Provisions</text>

  <path d="M230,100 C 230,140 240,140 240,190" class="arrow"/>
  <text x="265" y="155" class="text" text-anchor="middle" font-size="12px">Pushes/Signs</text>

  <path d="M290,75 C 310,75 330,150 360,210" class="arrow"/>
  <text x="340" y="120" class="text" text-anchor="middle" font-size="12px">Deploys</text>

  <path d="M500,255 C 450,255 310,255 310,255" class="arrow dashed-arrow"/>
  <text x="405" y="275" class="text" text-anchor="middle" font-size="12px">Verifies Attestation</text>

  <path d="M420,280 C 420,290 420,290 420,300" class="arrow"/>

  <path d="M690,225 C 670,225 640,235 610,240" class="arrow"/>
  <text x="650" y="220" class="text" text-anchor="middle" font-size="12px">Traffic</text>

  <path d="M480,325 C 490,325 490,325 500,325" class="arrow dashed-arrow"/>
</svg>
```

## Repository Map

The codebase is organized as a PNPM workspace managed by Turbo.

```
.
├── apps/
│   └── web/                  # Next.js 14 App Router application (Tailwind v4, Jest, Playwright)
├── deploy/
│   └── k8s/                  # Kustomize manifests
│       ├── base/             # Shared Kubernetes resources (Deployment, Service, Gateway, HTTPRoute)
│       └── overlays/         # Environment-specific patches (staging, production)
├── docs/                     # Architecture, security, onboarding, runbooks
├── infra/
│   └── terraform/            # Infrastructure as Code
│       ├── envs/             # Environment configurations (staging, production)
│       └── modules/          # Reusable modules (GKE, network, services, WIF)
├── packages/
│   ├── eslint-config-custom/ # Centralized ESLint rules (TypeScript, security, SonarJS)
│   └── tsconfig/             # Shared TypeScript presets
├── scripts/                  # Operational helpers (onboarding, infra bootstrap, CI/CD helpers, supply chain tooling)
├── .github/
│   └── workflows/            # CI/CD pipelines (CI, deploy, Terraform, CodeQL, security validation)
└── turbo.json                # Turbo configuration
```

## Technology Stack

- **Frontend:** Next.js 14 (App Router), React 18, TypeScript, Tailwind CSS v4.
- **Testing:** Jest, React Testing Library, Playwright.
- **Tooling:** PNPM workspaces, Turbo, ESLint, Prettier, Husky, Commitlint.
- **Infrastructure:** Terraform, GKE Autopilot, Artifact Registry, VPC networking, Workload Identity Federation.
- **DevOps:** Kustomize, Gateway API, Docker (distroless runtime).
- **Security:** Cosign, Syft, Grype, Trivy, Gitleaks, Semgrep, CodeQL, GCP Binary Authorization.

## Getting Started

### Prerequisites

Ensure the following tools are installed and authenticated:

1. **Node.js 20.x** – enable Corepack and activate pnpm 9:
   ```bash
   corepack enable && corepack prepare pnpm@9.12.0 --activate
   ```
2. **Docker** – required for local container builds and scanning.
3. **CLIs** – Google Cloud CLI (`gcloud`), Terraform CLI, and GitHub CLI (`gh`) with access to the target project.
4. **Playwright dependencies** – install browser dependencies once locally:
   ```bash
   pnpm --filter @ai-dev-platform/web exec playwright install --with-deps
   ```

### Setup

The provided scripts streamline the initial setup:

1. **One-shot setup**
   ```bash
   ./scripts/setup-all.sh
   ```
   Runs onboarding, infrastructure bootstrap, repository hardening, and editor extension management.
2. **Bootstrap infrastructure (optional standalone)**
   ```bash
   ./scripts/bootstrap-infra.sh
   ```
   Initializes Terraform backends, enables required GCP services, configures Workload Identity Federation, and offers applies per environment.
3. **Configure GitHub environments**
   ```bash
   ./scripts/configure-github-env.sh staging
   ./scripts/configure-github-env.sh prod
   ```
   Populates GitHub environment secrets/variables (e.g., WIF provider, Artifact Registry, GKE cluster metadata) from Terraform outputs.

### Local Development

Use pnpm filters to target the web application:

- **Run the web app**
  ```bash
  pnpm --filter @ai-dev-platform/web dev
  ```
- **Linting and type checking**
  ```bash
  pnpm lint
  pnpm type-check
  ```
- **Testing**
  ```bash
  # Unit tests
  pnpm --filter @ai-dev-platform/web test
  # E2E tests (Playwright starts a dev server when E2E_TARGET_URL is unset)
  pnpm --filter @ai-dev-platform/web test:e2e
  ```
- **Build the application**
  ```bash
  pnpm --filter @ai-dev-platform/web build
  ```

## CI/CD Pipeline

GitHub Actions enforces quality and security before any deployment.

1. **Continuous Integration (`.github/workflows/ci.yml`)**
   - Security scans: Gitleaks and Semgrep.
   - Quality gates: `pnpm install --frozen-lockfile`, lint, type-check, unit tests, build, format check.
   - Supply chain: build container, scan (Trivy/Grype), generate SBOM (Syft), sign (Cosign).
2. **Deployment (`deploy-staging.yml`, `deploy-production.yml`)**
   - Authenticates to GCP via Workload Identity Federation.
   - Rebuilds and signs the image, pushes to Artifact Registry, resolves the immutable digest.
   - Patches Kustomize overlays with the digest and Workload Identity annotation, applies manifests to GKE, waits for rollout.
   - Runs Playwright E2E tests against the live Gateway endpoint (staging always; production workflows can be extended similarly).

```svg
<svg width="900" height="350" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 350">
  <style>
    .pipeline-stage { fill: #ebf8ff; stroke: #4299e1; stroke-width: 2; rx: 10; }
    .job-box { fill: #ffffff; stroke: #a0aec0; stroke-width: 1; rx: 5; }
    .security-job { fill: #fff5f5; stroke: #fc8181; }
    .deploy-stage { fill: #f0fff4; stroke: #48bb78; }
    .text { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 14px; fill: #2d3748; }
    .title { font-size: 16px; font-weight: bold; }
    .trigger { font-style: italic; font-size: 12px; }
    .arrow { stroke: #718096; stroke-width: 2; fill: none; marker-end: url(#arrowhead); }
  </style>
  <defs>
    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#718096" />
    </marker>
  </defs>

  <text x="10" y="30" class="title">Triggers</text>
  <rect x="10" y="40" width="120" height="50" class="job-box"/>
  <text x="70" y="60" class="text" text-anchor="middle">PR / Push</text>
  <text x="70" y="80" class="text" text-anchor="middle">to `main`</text>

  <rect x="10" y="250" width="120" height="50" class="job-box"/>
  <text x="70" y="270" class="text" text-anchor="middle">Tag</text>
  <text x="70" y="290" class="text" text-anchor="middle">`v*.*.*`</text>

  <rect x="160" y="10" width="250" height="320" class="pipeline-stage"/>
  <text x="285" y="30" class="title" text-anchor="middle">Stage 1: Continuous Integration (ci.yml)</text>

  <rect x="180" y="50" width="210" height="60" class="job-box security-job"/>
  <text x="285" y="70" class="text" text-anchor="middle">Security Scans</text>
  <text x="285" y="90" class="text" text-anchor="middle">(Gitleaks, Semgrep)</text>

  <rect x="180" y="130" width="210" height="60" class="job-box"/>
  <text x="285" y="150" class="text" text-anchor="middle">Quality Gates</text>
  <text x="285" y="170" class="text" text-anchor="middle">(Lint, Type-check, Test, Build)</text>

  <rect x="180" y="210" width="210" height="100" class="job-box security-job"/>
  <text x="285" y="230" class="text" text-anchor="middle">Supply Chain</text>
  <text x="285" y="250" class="text" text-anchor="middle">Build Image</text>
  <text x="285" y="270" class="text" text-anchor="middle">Scan (Trivy/Grype)</text>
  <text x="285" y="290" class="text" text-anchor="middle">SBOM (Syft), Sign (Cosign)</text>

  <rect x="440" y="10" width="450" height="320" class="pipeline-stage deploy-stage"/>
  <text x="665" y="30" class="title" text-anchor="middle">Stage 2: Deployment (deploy-staging/production.yml)</text>

  <rect x="460" y="50" width="190" height="50" class="job-box"/>
  <text x="555" y="80" class="text" text-anchor="middle">Authenticate (WIF)</text>

  <rect x="460" y="120" width="190" height="80" class="job-box security-job"/>
  <text x="555" y="140" class="text" text-anchor="middle">Repeatable Build &amp; Sign</text>
  <text x="555" y="160" class="text" text-anchor="middle">Push to Artifact Registry</text>
  <text x="555" y="180" class="text" text-anchor="middle">Resolve Digest</text>

  <rect x="460" y="220" width="190" height="80" class="job-box"/>
  <text x="555" y="240" class="text" text-anchor="middle">Patch Kustomize Overlay</text>
  <text x="555" y="260" class="text" text-anchor="middle">(Set Digest &amp; KSA)</text>
  <text x="555" y="280" class="text" text-anchor="middle">kubectl apply &amp; wait</text>

  <rect x="680" y="120" width="190" height="80" class="job-box"/>
  <text x="775" y="140" class="title" text-anchor="middle">E2E Validation</text>
  <text x="775" y="160" class="text" text-anchor="middle">Resolve Gateway IP</text>
  <text x="775" y="180" class="text" text-anchor="middle">Run Playwright</text>

  <path d="M130,65 C 145,65 145,65 160,65" class="arrow"/>
  <path d="M130,275 C 145,275 145,275 160,275" class="arrow"/>

  <path d="M410,170 C 425,170 425,170 440,170" class="arrow"/>
  <text x="425" y="160" class="text" text-anchor="middle" font-size="12px">Gates</text>

  <path d="M555,100 C 555,110 555,110 555,120" class="arrow"/>
  <path d="M555,200 C 555,210 555,210 555,220" class="arrow"/>

  <path d="M650,260 C 665,260 665,180 680,180" class="arrow"/>
  <text x="675" y="230" class="text" text-anchor="middle" font-size="12px">Triggers</text>
</svg>
```

## Supply Chain Security

The platform applies rigorous supply-chain controls to preserve artifact integrity:

1. **Scanning:** Trivy and Grype run during CI and fail the pipeline on High/Critical (Trivy) or High (Grype) findings.
2. **SBOM generation:** Syft produces CycloneDX SBOMs that are uploaded as workflow artifacts.
3. **Keyless signing:** Cosign uses GitHub Actions OIDC (via WIF) to sign images and attest the SBOM with no long-lived keys.
4. **Binary Authorization:** GKE Autopilot clusters enforce Binary Authorization, allowing only signed and attested images to run.
5. **Immutable images:** Deployment workflows resolve tags to immutable digests and patch Kustomize overlays before applying manifests.

Developers can run the same steps locally with:

```bash
./scripts/container/supply-chain.sh build
./scripts/container/supply-chain.sh scan
./scripts/container/supply-chain.sh sbom
./scripts/container/supply-chain.sh sign
```

## Development Workflow

This project enforces a consistent workflow to maintain quality, security, and reproducibility:

1. **Branching:** Create feature branches from `main`; never commit directly to protected branches.
2. **Commits:** Follow Conventional Commits (`commitlint` enforces format).
3. **Pre-commit hooks:** Husky runs `gitleaks protect --staged` and `lint-staged` (ESLint + Prettier) on staged files.
4. **Pre-push hooks:** Verify editor extension lock consistency and capture git sync status.
5. **Pull requests:** Use the helper script to validate, push, and open PRs with auto-merge enabled:
   ```bash
   ./scripts/push-pr.sh
   ```
6. **Monitor merges:** Track PR status until merge (or failure) to ensure required checks pass:
   ```bash
   ./scripts/monitor-pr.sh
   ```
7. **Editor extensions:** Keep AI assistant extensions aligned across contributors:
   ```bash
   ./scripts/update-editor-extensions.sh
   ./scripts/verify-editor-extensions.sh --strict
   ```
   Commit changes to `config/editor-extensions.lock.json` whenever versions differ.

## Documentation

Detailed references are available in the `docs/` directory:

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Security Guardrails](docs/SECURITY.md)
- [Supply-Chain Hardening](docs/SUPPLY_CHAIN.md)
- [Infrastructure Automation](docs/INFRASTRUCTURE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Agent Protocols](docs/AGENT_PROTOCOLS.md)
- [Onboarding Guide](docs/ONBOARDING.md)
- [Release Runbook](docs/RELEASE_RUNBOOK.md)

Refer to these guides for environment-specific configuration, operational runbooks, and security guardrails.

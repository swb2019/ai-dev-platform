# Supply Chain Security

Phase 2 introduces containerized deployment for the web application and a hardened supply chain toolchain. This document captures the workflows for building Docker images, performing vulnerability scanning, generating SBOMs, and producing keyless signatures.

## Overview

| Capability          | Tool                  | Entry Point             |
| ------------------- | --------------------- | ----------------------- |
| Container build     | Docker                | `pnpm docker:build:web` |
| Vulnerability scans | Trivy & Grype         | `pnpm docker:scan:web`  |
| SBOM generation     | Syft (CycloneDX JSON) | `pnpm docker:sbom:web`  |
| Artifact signing    | Cosign (keyless)      | `pnpm docker:sign:sbom` |

The automation lives in `scripts/container/supply-chain.sh`, which orchestrates each workflow. Outputs such as SBOMs and signatures are written to `./artifacts/` and ignored by Git.

## Local Prerequisites

The dev container automatically installs Docker, pnpm, Trivy, Grype, Syft, and Cosign. If you are running locally, verify the following commands are available:

```bash
trivy --version
grype --version
syft --version
cosign version
```

If any tool is missing, rerun the post-create script or consult `.devcontainer/post-create.sh` for manual installation steps.

## Building the Image

```bash
pnpm docker:build:web
```

This builds `ai-dev-platform/web:local` using `apps/web/Dockerfile`. Supply a custom tag when needed:

```bash
bash scripts/container/supply-chain.sh build --tag ghcr.io/example/ai-dev-platform-web:dev
```

## Vulnerability Scanning

Run both scanners against the built image:

```bash
pnpm docker:scan:web
```

- Trivy fails on HIGH/CRITICAL vulnerabilities.
- Grype fails on HIGH vulnerabilities.
- Known exception: `CVE-2024-21538` is suppressed via `.trivyignore` after the build process rewrites Next.js' vendored `cross-spawn` bundle with v7.0.5.

## SBOM Generation

```bash
pnpm docker:sbom:web
```

The SBOM is written to `artifacts/sbom-web-cyclonedx.json`. Adjust the script arguments if you tagged the image differently.

## Keyless Signing

Set `COSIGN_EXPERIMENTAL=1` and sign artifacts with Cosign:

```bash
pnpm docker:sign:sbom
```

This emits `.sig` and `.cert` files alongside the SBOM. In CI, Cosign also signs the container image and attaches the SBOM as an attestation using GitHub’s OIDC workflow.

## CI/CD Integration

`.github/workflows/ci.yml` contains a `supply_chain` job that:

1. Builds and pushes the container image to GHCR.
2. Runs Trivy and Grype scans.
3. Generates a CycloneDX SBOM (via Syft) and uploads it as an artifact.
4. Signs the image and SBOM using Cosign keyless workflows and publishes the attestation.

The job requires `packages: write` and `id-token: write` permissions to interact with GHCR and Sigstore.

## Troubleshooting

- **Scanner failures**: Review the scanner output, patch dependencies, and rebuild before rerunning scans.
- **Cosign keyless auth**: Ensure `COSIGN_EXPERIMENTAL=1` and, in CI, that the job has `permissions.id-token: write`.
- **SBOM location**: The default path lives in `./artifacts/`; remove or rotate files between builds as needed.

Contact the AI Dev Platform Security maintainers before altering severity thresholds or skipping scans.

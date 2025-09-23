#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEFAULT_IMAGE_TAG="ai-dev-platform/web:local"
ARTIFACT_DIR="${REPO_ROOT}/artifacts"
SBOM_PATH="${ARTIFACT_DIR}/sbom-web-cyclonedx.json"

usage() {
  cat <<'USAGE'
Usage: supply-chain.sh <command> [options]

Commands:
  build [--tag <image-tag>]        Build the web application container image.
  scan  [--tag <image-tag>]        Run Trivy and Grype vulnerability scans against the image.
  sbom  [--tag <image-tag>]        Generate a CycloneDX SBOM for the image with Syft.
  sign  --file <path>              Keyless-sign an artifact (SBOM, tarball, etc.) with Cosign.

Environment:
  COSIGN_EXPERIMENTAL=1            Required for keyless signing with Cosign.

Examples:
  supply-chain.sh build --tag ai-dev-platform/web:dev
  supply-chain.sh scan
  supply-chain.sh sbom --tag ghcr.io/example/ai-dev-platform-web:latest
  supply-chain.sh sign --file artifacts/sbom-web-cyclonedx.json
USAGE
}

ensure_command() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "[supply-chain] Required command '$name' not found." >&2
    exit 1
  fi
}

parse_args() {
  local opt
  IMAGE_TAG="$DEFAULT_IMAGE_TAG"
  TARGET_FILE=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        IMAGE_TAG="$2"
        shift 2
        ;;
      --file)
        TARGET_FILE="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        POSITIONAL_ARGS+=("$1")
        shift
        ;;
    esac
  done
}

run_build() {
  ensure_command docker
  echo "[supply-chain] Building image '${IMAGE_TAG}' from ${REPO_ROOT}".
  docker build \
    --file "${REPO_ROOT}/apps/web/Dockerfile" \
    --tag "${IMAGE_TAG}" \
    "${REPO_ROOT}"
}

run_scan() {
  ensure_command trivy
  ensure_command grype
  echo "[supply-chain] Running Trivy vulnerability scan on '${IMAGE_TAG}'."
  local -a trivy_args=(image --exit-code 1 --severity HIGH,CRITICAL)
  if [ -f "${REPO_ROOT}/.trivyignore" ]; then
    trivy_args+=(--ignorefile "${REPO_ROOT}/.trivyignore")
  fi
  trivy "${trivy_args[@]}" "${IMAGE_TAG}"
  echo "[supply-chain] Running Grype vulnerability scan on '${IMAGE_TAG}'."
  local -a grype_args=("${IMAGE_TAG}" --fail-on High)
  if [ -f "${REPO_ROOT}/.grype.yaml" ]; then
    grype_args+=(--config "${REPO_ROOT}/.grype.yaml")
  fi
  grype "${grype_args[@]}"
}

run_sbom() {
  ensure_command syft
  mkdir -p "${ARTIFACT_DIR}"
  echo "[supply-chain] Generating SBOM at ${SBOM_PATH} for image '${IMAGE_TAG}'."
  syft "${IMAGE_TAG}" -o cyclonedx-json > "${SBOM_PATH}"
  echo "[supply-chain] SBOM generated: ${SBOM_PATH}"
}

run_sign() {
  ensure_command cosign
  if [[ -z "${TARGET_FILE}" ]]; then
    echo "[supply-chain] --file argument is required for sign command." >&2
    exit 1
  fi
  if [[ ! -f "${TARGET_FILE}" ]]; then
    echo "[supply-chain] Target file '${TARGET_FILE}' does not exist." >&2
    exit 1
  fi
  if [[ -z "${COSIGN_EXPERIMENTAL:-}" ]]; then
    echo "[supply-chain] COSIGN_EXPERIMENTAL environment variable must be set to 1 for keyless signing." >&2
    exit 1
  fi

  local signature_path="${TARGET_FILE}.sig"
  local certificate_path="${TARGET_FILE}.cert"

  echo "[supply-chain] Signing '${TARGET_FILE}' with Cosign (keyless)."
  cosign sign-blob "${TARGET_FILE}" \
    --output-signature "${signature_path}" \
    --output-certificate "${certificate_path}" \
    --yes

  echo "[supply-chain] Signature: ${signature_path}"
  echo "[supply-chain] Certificate: ${certificate_path}"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  COMMAND="$1"
  shift
  POSITIONAL_ARGS=()
  parse_args "$@"

  case "$COMMAND" in
    build)
      run_build
      ;;
    scan)
      run_scan
      ;;
    sbom)
      run_sbom
      ;;
    sign)
      run_sign
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"

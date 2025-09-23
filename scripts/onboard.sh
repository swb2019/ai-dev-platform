#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FLAG_FILE="${REPO_ROOT}/.onboarding_complete"

if [[ -f "${FLAG_FILE}" ]]; then
  printf '\n[onboard] Onboarding already completed. Remove %s to rerun.\n' "${FLAG_FILE}"
  exit 0
fi

welcome() {
  cat <<'MESSAGE'
==================================================
 AI Dev Platform - Onboarding Assistant
==================================================
This guided flow will verify local authentication, bootstrap secrets, and
prepare your IDE for autonomous development.
MESSAGE
}

prompt_enter() {
  local prompt_text=${1:-"Press ENTER to continue..."}
  read -rp "${prompt_text}" _
}

ensure_github_cli() {
  printf '\n[onboard] Step 1: Checking GitHub CLI authentication...\n'
  while true; do
    if gh auth status >/dev/null 2>&1; then
      printf '[onboard] GitHub CLI is authenticated.\n'
      break
    fi

    cat <<'GHMSG'
[onboard] GitHub CLI authentication is required.
Run `gh auth login` in this terminal, complete the prompts, then retry.
GHMSG
    prompt_enter "Press ENTER once GitHub authentication is complete to retry: "
  done
}

ensure_git_remote() {
  printf '\n[onboard] Step 2: Verifying git access to origin...\n'
  while true; do
    if git -C "${REPO_ROOT}" ls-remote origin HEAD >/dev/null 2>&1; then
      printf '[onboard] Git remote origin is reachable.\n'
      break
    fi

    cat <<'GITMSG'
CRITICAL ERROR: Git authentication failed. Ensure your SSH Agent is forwarded (if using SSH)
OR that 'gh auth setup-git' is configured (if using HTTPS). Refer to docs/ONBOARDING.md for troubleshooting.
GITMSG
    prompt_enter "Resolve the issue, then press ENTER to retry the git check: "
  done
}

ensure_infisical_cli_available() {
  if command -v infisical >/dev/null 2>&1; then
    return 0
  fi

  cat <<'INFICLI'
[onboard] Infisical CLI was not found on PATH.
The post-create script should install it automatically. If you rebuilt before it
finished, run `npm install -g @infisical/cli` or rebuild the container, then retry.
INFICLI
  return 1
}

INFISICAL_FETCH_SUCCESS_MESSAGE='[onboard] Secrets pulled successfully.'
INFISICAL_FETCH_PROMPT='Resolve the Infisical pull error and press ENTER to retry: '

infisical_supports_command() {
  local subcommand="$1"
  local help_output=""

  if ! help_output="$(infisical help 2>&1)"; then
    return 1
  fi

  if printf '%s\n' "$help_output" | grep -E "^[[:space:]]+${subcommand}([[:space:]]|$)" >/dev/null; then
    return 0
  fi

  return 1
}

infisical_fetch_secrets() {
  if infisical_supports_command "pull"; then
    INFISICAL_FETCH_SUCCESS_MESSAGE='[onboard] Secrets pulled successfully.'
    INFISICAL_FETCH_PROMPT='Resolve the Infisical pull error and press ENTER to retry: '
    infisical pull
    return
  fi

  INFISICAL_FETCH_PROMPT='Resolve the Infisical export error and press ENTER to retry: '
  local env_name="${INFISICAL_ENVIRONMENT:-dev}"
  local configured_path="${INFISICAL_SECRETS_FILE:-.env.local}"
  local output_path="$configured_path"

  if [[ "${output_path}" != /* ]]; then
    output_path="${REPO_ROOT}/${output_path}"
  fi

  mkdir -p "$(dirname "${output_path}")"
  printf '[onboard] Detected Infisical CLI without legacy pull command. Exporting secrets for env "%s" to %s.\n' "${env_name}" "${output_path}"
  INFISICAL_FETCH_SUCCESS_MESSAGE="[onboard] Secrets exported to ${output_path}."
  (cd "${REPO_ROOT}" && infisical --silent export --env="${env_name}" --format=dotenv --output-file="${output_path}")
}

run_infisical_bootstrap() {
  printf '\n[onboard] Step 3: Authenticating with Infisical...\n'
  while true; do
    if ensure_infisical_cli_available && infisical login; then
      printf '[onboard] Infisical login succeeded.\n'
      break
    fi
    prompt_enter "Address the issue (install/login) and press ENTER to retry Infisical login: "
  done

  printf '\n[onboard] Step 4: Retrieving development secrets with Infisical...\n'
  while true; do
    if infisical_fetch_secrets; then
      printf '%s\n' "${INFISICAL_FETCH_SUCCESS_MESSAGE}"
      break
    fi
    prompt_enter "${INFISICAL_FETCH_PROMPT}"
  done
}

ensure_node_dependencies() {
  printf '\n[onboard] Step 5: Verifying pnpm dependencies...\n'
  if ! command -v pnpm >/dev/null 2>&1; then
    printf '[onboard] pnpm >=9 is required. Install pnpm and rerun onboarding.\n'
    exit 1
  fi

  if [[ -d "${REPO_ROOT}/node_modules" ]]; then
    printf '[onboard] node_modules already present. Skipping pnpm install.\n'
    return
  fi

  (cd "${REPO_ROOT}" && pnpm install)
}

require_command() {
  local cmd="$1"
  local hint="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    return
  fi
  printf '[onboard] Required command "%s" not found. %s\n' "$cmd" "$hint"
  exit 1
}

ensure_gcloud_adc() {
  require_command gcloud "Install the Google Cloud SDK from https://cloud.google.com/sdk/docs/install"
  while true; do
    if gcloud auth application-default print-access-token >/dev/null 2>&1; then
      break
    fi
    cat <<'ADCMSG'
[onboard] Google Cloud application-default credentials not found.
Run `gcloud auth application-default login` in this terminal, complete the prompts, then press ENTER to continue.
ADCMSG
    prompt_enter
  done
}

run_terraform_apply() {
  local tf_dir="$1"
  local project_id="$2"

  require_command docker "Install Docker or use the dev container where it is preinstalled."
  ensure_gcloud_adc

  if [[ ! -d "${tf_dir}" ]]; then
    printf '[onboard] Terraform directory %s not found.\n' "${tf_dir}"
    return 1
  fi

  local gcloud_config_dir="${HOME}/.config/gcloud"
  if [[ ! -d "${gcloud_config_dir}" ]]; then
    printf '[onboard] Expected gcloud config directory %s not found.\n' "${gcloud_config_dir}"
    return 1
  fi

  printf '\n[onboard] Running Terraform init/apply via Docker (hashicorp/terraform:1.8.5)...\n'
  docker run --rm \
    -v "${tf_dir}":/workspace \
    -v "${gcloud_config_dir}":/root/.config/gcloud:ro \
    -w /workspace \
    -e GOOGLE_PROJECT="${project_id}" \
    hashicorp/terraform:1.8.5 init -input=false

  docker run --rm \
    -v "${tf_dir}":/workspace \
    -v "${gcloud_config_dir}":/root/.config/gcloud:ro \
    -w /workspace \
    hashicorp/terraform:1.8.5 apply -input=false -auto-approve

  printf '\n[onboard] Terraform apply complete. Capturing key outputs...\n'
  docker run --rm \
    -v "${tf_dir}":/workspace \
    -w /workspace \
    hashicorp/terraform:1.8.5 output > terraform-outputs.txt
  printf '[onboard] Terraform outputs saved to %s/terraform-outputs.txt.\n' "${tf_dir}"
  cat <<'OUTPUTMSG'
[onboard] Use `terraform output -raw <name>` (or inspect terraform-outputs.txt) to populate GitHub secrets/variables as described in docs/INFRASTRUCTURE.md.
OUTPUTMSG
}

configure_gcp_infrastructure() {
  printf '\n[onboard] Step 6: Optional Terraform & GCP configuration.\n'
  read -rp "Configure Terraform environment files now? (y/N): " response
  case "${response}" in
    y|Y|yes|YES)
      ;;
    *)
      printf '[onboard] Skipping Terraform configuration for now.\n'
      return
      ;;
  esac

  local tf_dir="${REPO_ROOT}/infra/terraform/envs/prod"
  local tfvars_path="${tf_dir}/terraform.tfvars"
  local backend_path="${tf_dir}/backend.auto.tfbackend"

  local repo_full=""
  if repo_full=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null); then
    true
  else
    local origin_url="$(git -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || echo '')"
    if [[ "${origin_url}" =~ github.com[:/]{1}([^/]+)/([^/.]+) ]]; then
      repo_full="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
    fi
  fi

  if [[ -z "${repo_full}" ]]; then
    repo_full="your-org/ai-dev-platform"
  fi

  local repo_owner="${repo_full%%/*}"
  local repo_name="${repo_full##*/}"

  local entered_project_id=""

  if [[ -f "${tfvars_path}" ]]; then
    printf '[onboard] %s already exists. Remove it to regenerate.\n' "${tfvars_path}"
  else
    printf '\nProvide values for terraform.tfvars (ENTER for defaults).\n'
    while [[ -z "${entered_project_id}" ]]; do
      read -rp "GCP project ID: " entered_project_id
      if [[ -z "${entered_project_id}" ]]; then
        printf '[onboard] A GCP project ID is required to provision infrastructure.\n'
      fi
    done
    read -rp "Default region [us-central1]: " region
    local region_value="${region:-us-central1}"
    read -rp "GKE location (region or zone) [${region_value}]: " location
    local location_value="${location:-${region_value}}"
    read -rp "Artifact Registry repository ID [ai-dev-platform]: " registry
    read -rp "GKE cluster name [ai-dev-autopilot]: " cluster_name
    read -rp "VPC name prefix [ai-dev]: " network_name

    cat <<EOT >"${tfvars_path}"
project_id           = "${entered_project_id}"
region               = "${region_value}"
location             = "${location_value}"
github_org           = "${repo_owner}"
github_repo          = "${repo_name}"
cluster_name         = "${cluster_name:-ai-dev-autopilot}"
network_name         = "${network_name:-ai-dev}"
release_channel      = "REGULAR"
artifact_registry_repo = "${registry:-ai-dev-platform}"
EOT
    printf '[onboard] Created %s\n' "${tfvars_path}"
  fi

  local backend_project="${entered_project_id}"
  if [[ -z "${backend_project}" && -f "${tfvars_path}" ]]; then
    backend_project=$(grep -E '^project_id' "${tfvars_path}" | awk -F '"' '{print $2}' || true)
  fi

  if [[ -f "${backend_path}" ]]; then
    printf '[onboard] %s already exists. Remove it to regenerate.\n' "${backend_path}"
  else
    read -rp "Terraform state bucket name: " state_bucket
    read -rp "Terraform state prefix [ai-dev-platform/prod]: " state_prefix
    read -rp "Terraform state location/region [US]: " state_location

    cat <<EOT >"${backend_path}"
bucket  = "${state_bucket}"
prefix  = "${state_prefix:-ai-dev-platform/prod}"
project = "${backend_project}"
location = "${state_location:-US}"
EOT
    printf '[onboard] Created %s\n' "${backend_path}"
  fi

  cat <<'NEXTSTEPS'

[onboard] Terraform configuration files generated. Next steps:
  • Ensure the Terraform state bucket exists and run `terraform -chdir=infra/terraform/envs/prod init`.
  • After the first `terraform apply`, capture outputs (service account emails, WIF provider name, cluster name).
  • Populate GitHub secrets and variables listed in docs/INFRASTRUCTURE.md using those outputs.
NEXTSTEPS

  read -rp "Run Terraform init/apply now via Docker? (y/N): " run_tf
  case "${run_tf}" in
    y|Y|yes|YES)
      run_terraform_apply "${tf_dir}" "${backend_project}"
      ;;
    *)
      printf '[onboard] You can run Terraform later with `terraform -chdir=infra/terraform/envs/prod apply`.\n'
      ;;
  esac
}

confirm_cursor_setup() {
  cat <<'CURSORMESSAGE'

[onboard] Step 7: Configure Cursor IDE for autonomous operation.
- Enable "Auto-Run" in Cursor Settings.
- Sign into the Claude Code extension.
- Sign into the OpenAI Codex (ChatGPT) extension if available.
CURSORMESSAGE
  prompt_enter "Press ENTER once the Cursor IDE configuration is complete: "
}

collect_final_confirmation() {
  printf '\n[onboard] Step 8: Final confirmation.\n'
  while true; do
    read -rp "Type 'yes' to confirm that onboarding is complete: " response
    case "${response}" in
      yes|y|Y|YES|Yes)
        printf '[onboard] Confirmation received.\n'
        break
        ;;
      *)
        printf "[onboard] Please enter 'yes' once all steps are finished.\n"
        ;;
    esac
  done
}

finalize() {
  touch "${FLAG_FILE}"
  cat <<'DONE'

[onboard] Onboarding complete. The flag file has been recorded at .onboarding_complete.
You can rerun the onboarding by removing that file and invoking scripts/onboard.sh manually.
DONE
}

main() {
  welcome
  ensure_github_cli
  ensure_git_remote
  run_infisical_bootstrap
  ensure_node_dependencies
  configure_gcp_infrastructure
  confirm_cursor_setup
  collect_final_confirmation
  finalize
}

main "$@"

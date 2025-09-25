#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "")"
if [[ -z "$REPO_ROOT" ]]; then
  echo "❌ Unable to determine repository root. Run this script inside the repo." >&2
  exit 1
fi
cd "$REPO_ROOT"

RESTORE_STASH=0
STASH_REF=""
TF_GITHUB_ORG=${TF_GITHUB_ORG:-}
TF_GITHUB_REPO=${TF_GITHUB_REPO:-}
TF_PROJECT_ID=${TF_PROJECT_ID:-}
TF_PROJECT_NUMBER=${TF_PROJECT_NUMBER:-}

collect_tf_vars() {
  require_cmd jq
  if [[ -z "$TF_GITHUB_ORG" ]]; then
    read -rp "GitHub organization or username: " TF_GITHUB_ORG
  fi
  if [[ -z "$TF_GITHUB_REPO" ]]; then
    read -rp "GitHub repository name: " TF_GITHUB_REPO
  fi
  if [[ -z "$TF_PROJECT_ID" ]]; then
    read -rp "GCP project ID: " TF_PROJECT_ID
  fi

  if [[ -z "$TF_GITHUB_ORG" || -z "$TF_GITHUB_REPO" || -z "$TF_PROJECT_ID" ]]; then
    echo "❌ All variables are required." >&2
    exit 1
  fi

  TF_PROJECT_NUMBER=$(gcloud auth application-default print-access-token \
    | xargs -I{} curl -s -H "Authorization: Bearer {}" \
      "https://cloudresourcemanager.googleapis.com/v1/projects/${TF_PROJECT_ID}" \
    | jq -r '.projectNumber' 2>/dev/null || true)

  if [[ -z "$TF_PROJECT_NUMBER" || "$TF_PROJECT_NUMBER" == "null" ]]; then
    echo "❌ Unable to determine project number for $TF_PROJECT_ID. Ensure your credentials have permission to view the project." >&2
    exit 1
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "❌ Missing required command: $1" >&2
    exit 1
  fi
}

confirm() {
  local prompt=$1
  local reply
  read -rp "$prompt [y/N]: " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

cleanup() {
  if [[ "$RESTORE_STASH" -eq 1 && -n "$STASH_REF" ]]; then
    echo "🔄 Restoring previous worktree state ($STASH_REF)..."
    if git stash pop "$STASH_REF" >/dev/null 2>&1; then
      echo "✅ Restored worktree from $STASH_REF."
      RESTORE_STASH=0
      STASH_REF=""
    else
      echo "⚠️  Failed to automatically restore stash $STASH_REF. You may need to run 'git stash pop'." >&2
    fi
  fi
}

trap cleanup EXIT

ensure_gcloud_auth() {
  if ! command -v gcloud >/dev/null 2>&1; then
    echo "❌ gcloud CLI not found. Install the Google Cloud SDK before continuing." >&2
    exit 1
  fi

  if gcloud auth application-default print-access-token >/dev/null 2>&1; then
    return
  fi

  echo "⚠️  Google Cloud application-default credentials are missing or expired."
  if ! confirm "Authenticate with 'gcloud auth application-default login --no-launch-browser'?"; then
    echo "❌ Unable to continue without Google Cloud credentials." >&2
    exit 1
  fi

  gcloud auth application-default login --no-launch-browser

  if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
    echo "❌ Authentication failed. Please complete gcloud authentication and rerun the script." >&2
    exit 1
  fi
}

import_existing_resources() {
  local env=$1
  local tf_dir=$2
  local project_id=$TF_PROJECT_ID
  local project_number=$TF_PROJECT_NUMBER
  local region="us-central1"
  local network_name="ai-dev-${env}"
  local repo_id="ai-dev-platform-${env}"
  local cluster_name="ai-dev-${env}-autopilot"
  local runtime_sa="web-runtime-${env}"
  local api_sa="api-gateway-runtime-${env}"
  local github_sa="github-terraform-${env}"
  local pool_id="github-wif-pool-${env}"
  local provider_id="github-provider-${env}"

  local state_list
  state_list=$(terraform -chdir="$tf_dir" state list 2>/dev/null || true)

  local -a imports=(
    "google_project_service.required[\"artifactregistry.googleapis.com\"]|${project_id}/artifactregistry.googleapis.com"
    "google_project_service.required[\"container.googleapis.com\"]|${project_id}/container.googleapis.com"
    "google_project_service.required[\"containeranalysis.googleapis.com\"]|${project_id}/containeranalysis.googleapis.com"
    "google_project_service.required[\"iamcredentials.googleapis.com\"]|${project_id}/iamcredentials.googleapis.com"
    "google_project_service.required[\"sts.googleapis.com\"]|${project_id}/sts.googleapis.com"
    "google_project_service.required[\"compute.googleapis.com\"]|${project_id}/compute.googleapis.com"
    "google_project_service.required[\"networkservices.googleapis.com\"]|${project_id}/networkservices.googleapis.com"
    "google_project_service.required[\"trafficdirector.googleapis.com\"]|${project_id}/trafficdirector.googleapis.com"
    "google_artifact_registry_repository.containers|projects/${project_id}/locations/${region}/repositories/${repo_id}"
    "google_service_account.runtime|projects/${project_id}/serviceAccounts/${runtime_sa}@${project_id}.iam.gserviceaccount.com"
    "google_service_account.api_gateway_runtime|projects/${project_id}/serviceAccounts/${api_sa}@${project_id}.iam.gserviceaccount.com"
    "module.gke.google_service_account.cluster_sa|projects/${project_id}/serviceAccounts/${cluster_name}-gke@${project_id}.iam.gserviceaccount.com"
    "module.network.google_compute_network.this|projects/${project_id}/global/networks/${network_name}-vpc"
    "module.network.google_compute_subnetwork.primary|projects/${project_id}/regions/${region}/subnetworks/${network_name}-primary"
    "module.network.google_compute_subnetwork.secondary[0]|projects/${project_id}/regions/${region}/subnetworks/${network_name}-pods"
    "module.network.google_compute_router.this|projects/${project_id}/regions/${region}/routers/${network_name}-router"
    "module.network.google_compute_router_nat.this|projects/${project_id}/regions/${region}/routers/${network_name}-router/${network_name}-nat"
    "module.gke.google_container_cluster.this|projects/${project_id}/locations/${region}/clusters/${cluster_name}"
    "module.wif.google_iam_workload_identity_pool.this|projects/${project_id}/locations/global/workloadIdentityPools/${pool_id}"
    "module.wif.google_iam_workload_identity_pool_provider.github|projects/${project_id}/locations/global/workloadIdentityPools/${pool_id}/providers/${provider_id}"
    "module.wif.google_service_account.github|projects/${project_id}/serviceAccounts/${github_sa}@${project_id}.iam.gserviceaccount.com"
    "google_project_iam_member.runtime_permissions[\"roles/logging.logWriter\"]|projects/${project_id} roles/logging.logWriter serviceAccount:${runtime_sa}@${project_id}.iam.gserviceaccount.com"
    "google_project_iam_member.runtime_permissions[\"roles/monitoring.metricWriter\"]|projects/${project_id} roles/monitoring.metricWriter serviceAccount:${runtime_sa}@${project_id}.iam.gserviceaccount.com"
    "google_project_iam_member.runtime_permissions[\"roles/artifactregistry.reader\"]|projects/${project_id} roles/artifactregistry.reader serviceAccount:${runtime_sa}@${project_id}.iam.gserviceaccount.com"
    "google_project_iam_member.api_gateway_runtime_permissions[\"roles/logging.logWriter\"]|projects/${project_id} roles/logging.logWriter serviceAccount:${api_sa}@${project_id}.iam.gserviceaccount.com"
    "google_project_iam_member.api_gateway_runtime_permissions[\"roles/monitoring.metricWriter\"]|projects/${project_id} roles/monitoring.metricWriter serviceAccount:${api_sa}@${project_id}.iam.gserviceaccount.com"
    "google_project_iam_member.api_gateway_runtime_permissions[\"roles/artifactregistry.reader\"]|projects/${project_id} roles/artifactregistry.reader serviceAccount:${api_sa}@${project_id}.iam.gserviceaccount.com"
    "module.wif.google_project_iam_member.terraform_roles[\"roles/iam.serviceAccountTokenCreator\"]|projects/${project_id} roles/iam.serviceAccountTokenCreator serviceAccount:${github_sa}@${project_id}.iam.gserviceaccount.com"
    "module.wif.google_project_iam_member.terraform_roles[\"roles/container.admin\"]|projects/${project_id} roles/container.admin serviceAccount:${github_sa}@${project_id}.iam.gserviceaccount.com"
    "module.wif.google_project_iam_member.terraform_roles[\"roles/artifactregistry.admin\"]|projects/${project_id} roles/artifactregistry.admin serviceAccount:${github_sa}@${project_id}.iam.gserviceaccount.com"
    "module.wif.google_project_iam_member.terraform_roles[\"roles/resourcemanager.projectIamAdmin\"]|projects/${project_id} roles/resourcemanager.projectIamAdmin serviceAccount:${github_sa}@${project_id}.iam.gserviceaccount.com"
    "module.wif.google_service_account_iam_member.github_wi|projects/${project_id}/serviceAccounts/${github_sa}@${project_id}.iam.gserviceaccount.com roles/iam.workloadIdentityUser principalSet://iam.googleapis.com/projects/${project_number}/locations/global/workloadIdentityPools/${pool_id}/attribute.repository/${TF_GITHUB_ORG}/${TF_GITHUB_REPO}"
  )

  local entry
  for entry in "${imports[@]}"; do
    local address=${entry%%|*}
    local resource_id=${entry#*|}
    if grep -Fxq "$address" <<<"$state_list"; then
      echo "ℹ️  Terraform state already includes $address"
      continue
    fi
    echo "🔄 Importing existing resource: $address"
    set +e
    local import_output
    import_output=$(TF_VAR_project_id="$TF_PROJECT_ID" \
      TF_VAR_github_org="$TF_GITHUB_ORG" \
      TF_VAR_github_repo="$TF_GITHUB_REPO" \
      terraform -chdir="$tf_dir" import -input=false "$address" "$resource_id" 2>&1)
    local import_status=$?
    set -e
    if [[ $import_status -eq 0 ]]; then
      state_list+=$'\n'$address
      echo "✅ Imported $address"
    else
      if [[ "$import_output" == *"NOT_FOUND"* || "$import_output" == *"not found"* ]]; then
        echo "ℹ️  Resource $address not found in project; skipping import."
      else
        echo "⚠️  Unable to import $address:"
        echo "$import_output"
      fi
    fi
  done
}

push_branch() {
  local branch
  branch="$(git rev-parse --abbrev-ref HEAD)"

  if confirm "Push branch '$branch' to origin?"; then
    set +e
    local push_output
    push_output=$(git push -u origin "$branch" 2>&1)
    local push_status=$?
    set -e

    if [[ $push_status -eq 0 ]]; then
      printf '%s\n' "$push_output"
      return
    fi

    printf '%s\n' "$push_output"

    if [[ "$push_output" == *"non-fast-forward"* ]]; then
      if confirm "Remote branch has diverged. Force push with --force-with-lease?"; then
        set +e
        push_output=$(git push --force-with-lease origin "$branch" 2>&1)
        push_status=$?
        set -e
        printf '%s\n' "$push_output"
        if [[ $push_status -ne 0 ]]; then
          echo "❌ Force push failed. Resolve the issue and rerun the script." >&2
          exit $push_status
        fi
      else
        echo "⚠️  Skipping git push due to divergence."
      fi
    else
      echo "❌ git push failed. Resolve the error above and rerun the script." >&2
      exit $push_status
    fi
  else
    echo "⚠️  Skipping git push."
  fi
}

terraform_apply_env() {
  local env=$1
  local tf_dir="$REPO_ROOT/infra/terraform/envs/$env"

  require_cmd terraform
  echo "🔧 Running Terraform for '$env' (directory: $tf_dir)"

  local init_args=("-chdir=$tf_dir" init -upgrade)
  if [[ -f "$tf_dir/backend.auto.tfbackend" ]]; then
    init_args+=(-backend-config="$tf_dir/backend.auto.tfbackend")
  elif [[ -f "$tf_dir/backend.hcl" ]]; then
    init_args+=(-backend-config="$tf_dir/backend.hcl")
  fi

  terraform "${init_args[@]}"

  import_existing_resources "$env" "$tf_dir"

  local plan_args=(-chdir="$tf_dir" plan -input=false \
    -var "github_org=$TF_GITHUB_ORG" \
    -var "github_repo=$TF_GITHUB_REPO" \
    -var "project_id=$TF_PROJECT_ID")

  local apply_args=(-chdir="$tf_dir" apply -input=false \
    -var "github_org=$TF_GITHUB_ORG" \
    -var "github_repo=$TF_GITHUB_REPO" \
    -var "project_id=$TF_PROJECT_ID")

  if confirm "Generate terraform plan for '$env'?"; then
    terraform "${plan_args[@]}" -out=tfplan
  fi

  if confirm "Apply terraform changes for '$env'?"; then
    if [[ -f "$tf_dir/tfplan" ]]; then
      terraform -chdir="$tf_dir" apply -input=false tfplan
      rm -f "$tf_dir/tfplan"
    else
      terraform "${apply_args[@]}"
    fi
  else
    echo "⚠️  Skipping terraform apply for '$env'."
  fi

  rm -f "$tf_dir/tfplan"
  rm -rf "$tf_dir/.terraform" "$tf_dir/.terraform.lock.hcl"
}

bootstrap_github_env() {
  local env=$1
  local script_path="$REPO_ROOT/scripts/bootstrap-github-env.sh"

  if [[ ! -x "$script_path" ]]; then
    echo "⚠️  $script_path is missing or not executable; skipping environment sync for '$env'."
    return
  fi

  echo "ℹ️  Syncing GitHub environment variables for '$env'."

  if confirm "Run DRY_RUN sync for '$env'?"; then
    DRY_RUN=1 "$script_path" "$env"
  fi

  if confirm "Apply GitHub environment sync for '$env'?"; then
    "$script_path" "$env"
  else
    echo "⚠️  Skipping GitHub env sync for '$env'."
  fi
}

show_post_apply_reminders() {
  cat <<'MSG'

✅ Terraform is complete. Retrieve the latest `api_gateway_runtime_service_account_email`
   from `terraform output` or the updated `terraform-outputs.txt`, then configure the
   following GitHub Actions secrets/variables for both staging and production:

   - GCP_RUNTIME_SERVICE_ACCOUNT            (existing web runtime)
   - GCP_API_GATEWAY_SERVICE_ACCOUNT        (new gateway runtime)
   - Region/project/location values referenced by the deploy workflows

   Example CLI update:
     gh secret set GCP_API_GATEWAY_SERVICE_ACCOUNT --body <service-account-email>

MSG
}

main() {
  require_cmd git

  if [[ -n "$(git status --porcelain)" ]]; then
    echo "⚠️  Worktree has uncommitted changes."
    if confirm "Create a temporary stash (including untracked files) so the script can proceed?"; then
      local stash_msg
      stash_msg="finish-api-gateway-setup $(date +%Y-%m-%dT%H:%M:%S)"
      if git stash push -u -m "$stash_msg" >/dev/null; then
        STASH_REF="$(git stash list | head -n1 | cut -d: -f1)"
        RESTORE_STASH=1
        echo "🧺 Stored worktree state as $STASH_REF. It will be restored when the script exits."
      else
        echo "❌ Failed to create a stash. Please resolve your working tree state and retry." >&2
        exit 1
      fi
    else
      echo "❌ Please commit, stash, or discard changes before running this script." >&2
      exit 1
    fi
  fi

  ensure_gcloud_auth
  collect_tf_vars
  push_branch

  for env in staging prod; do
    ensure_gcloud_auth
    terraform_apply_env "$env"
    bootstrap_github_env "$env"
  done

  show_post_apply_reminders

  echo "🎉 Maintainer tasks finished (or skipped at your request)."
}

main "$@"

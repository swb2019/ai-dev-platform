#!/usr/bin/env bash
# Uninstall helper for the AI Dev Platform. Cleans repository artifacts,
# optional developer-home caches, and (optionally) runs terraform destroy for
# each environment before wiping local Terraform state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORCE=0
DRY_RUN=0
INCLUDE_HOME=0
DESTROY_TERRAFORM=0
SUMMARY_FILE="$ROOT_DIR/uninstall-terraform-summary.json"

usage() {
  cat <<'USAGE'
Usage: ./scripts/uninstall.sh [options]

Options:
  --force             Skip interactive confirmation.
  --dry-run           Show what would be removed without deleting anything.
  --include-home      Also remove Codex/Cursor caches under $HOME.
  --destroy-cloud     Run `terraform destroy` in infra/terraform/envs/* before cleaning files.
  -h, --help          Show this message.

Examples:
  ./scripts/uninstall.sh --dry-run
  ./scripts/uninstall.sh --include-home --destroy-cloud
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --include-home) INCLUDE_HOME=1; shift ;;
    --destroy-cloud) DESTROY_TERRAFORM=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

cd "$ROOT_DIR"

if [[ ! -f "$ROOT_DIR/package.json" ]]; then
  echo "Error: script must be run from the repository root." >&2
  exit 1
fi

prompt() {
  local message="$1"
  if (( FORCE )); then
    return 0
  fi
  read -r -p "$message [y/N] " response
  case "$response" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *) return 1 ;;
  esac
}

remove_path() {
  local target="$1"
  if [[ -z "$target" ]]; then
    return
  fi
  if [[ ! -e "$target" && ! -L "$target" ]]; then
    return
  fi
  if (( DRY_RUN )); then
    echo "[dry-run] rm -rf $target"
  else
    rm -rf "$target"
    echo "Removed $target"
  fi
}

repo_targets=(
  "$ROOT_DIR/node_modules"
  "$ROOT_DIR/.pnpm-store"
  "$ROOT_DIR/.turbo"
  "$ROOT_DIR/.playwright"
  "$ROOT_DIR/.cache"
  "$ROOT_DIR/.pnpm-debug.log"
  "$ROOT_DIR/.onboarding_complete"
  "$ROOT_DIR/tmp"
  "$ROOT_DIR/artifacts"
  "$ROOT_DIR/apps/web/node_modules"
  "$ROOT_DIR/apps/web/.next"
  "$ROOT_DIR/apps/web/playwright-report"
  "$ROOT_DIR/apps/web/test-results"
  "$ROOT_DIR/apps/web/playwright-report.zip"
  "$ROOT_DIR/packages"/*/node_modules
  "$ROOT_DIR/.git/hooks/pre-commit"
  "$ROOT_DIR/.git/hooks/pre-push"
)

terraform_local_targets=(
  "$ROOT_DIR/infra/terraform/.terraform"
  "$ROOT_DIR/infra/terraform/.terraform.lock.hcl"
  "$ROOT_DIR/infra/terraform/terraform.tfstate"
  "$ROOT_DIR/infra/terraform/terraform.tfstate.backup"
  "$ROOT_DIR/infra/terraform/envs"/*/.terraform
  "$ROOT_DIR/infra/terraform/envs"/*/.terraform.lock.hcl
  "$ROOT_DIR/infra/terraform/envs"/*/terraform.tfstate
  "$ROOT_DIR/infra/terraform/envs"/*/terraform.tfstate.backup
)

home_targets=(
  "$HOME/.cursor"
  "$HOME/.codex"
  "$HOME/.cache/Cursor"
  "$HOME/.cache/ms-playwright"
  "$HOME/.cache/pnpm"
  "$HOME/.local/share/pnpm"
  "$HOME/.pnpm-store"
  "$HOME/.turbo"
  "$HOME/.npm"
)

summaries=()
json_entries=()

append_summary() {
  local env="$1" status="$2" message="$3" backend="$4"
  summaries+=("$env: $status - $message (backend: $backend)")
  json_entries+=("  {\"environment\":\"$env\",\"status\":\"$status\",\"backend\":\"$backend\",\"message\":\"$message\"}")
}

get_backend() {
  local env_dir="$1"
  python3 - <<'PY'
import pathlib, sys, re
path = pathlib.Path(sys.argv[1])
backend_file = path / 'backend.tf'
backend = 'unknown'
if backend_file.exists():
    text = backend_file.read_text()
    m = re.search(r'backend\s+"([^"]+)"', text)
    if m:
        backend = m.group(1)
print(backend)
PY
 "$env_dir"
}

run_terraform_destroy() {
  local env_dir="$1" backend warning=""
  backend=$(get_backend "$env_dir")
  echo "— Terraform destroy in $env_dir (backend: $backend)"
  case "$backend" in
    s3|gcs|azurerm|remote|http)
      warning="Remote backend detected ($backend); ensure remote state is cleaned if destroy fails."
      echo "  $warning" >&2
      ;;
  esac

  if (( DRY_RUN )); then
    append_summary "$env_dir" "skipped" "dry-run" "$backend"
    return
  fi

  if ! command -v terraform >/dev/null 2>&1; then
    echo "Terraform binary not found. Skipping cloud destruction for $env_dir" >&2
    append_summary "$env_dir" "skipped" "terraform unavailable" "$backend"
    return
  fi

  pushd "$env_dir" >/dev/null
  if ! terraform init -upgrade >/dev/null; then
    echo "terraform init failed in $env_dir" >&2
    append_summary "$env_dir" "failure" "terraform init failed" "$backend"
    popd >/dev/null
    return
  fi

  if terraform destroy -auto-approve; then
    append_summary "$env_dir" "success" "destroy succeeded" "$backend"
  else
    echo "terraform destroy failed in $env_dir" >&2
    append_summary "$env_dir" "failure" "destroy failed" "$backend"
  fi
  popd >/dev/null
}

if ! prompt "This will remove generated artifacts from $ROOT_DIR. Proceed?"; then
  echo "Aborted."
  exit 0
fi

if (( DESTROY_TERRAFORM )); then
  echo "Beginning Terraform destruction..."
  for env_dir in "$ROOT_DIR"/infra/terraform/envs/*; do
    [[ -d "$env_dir" ]] || continue
    run_terraform_destroy "$env_dir"
  done
  echo "Terraform destruction summary:"
  printf '  - %s\n' "${summaries[@]}"
  if (( ! DRY_RUN )); then
    printf '[\n%s\n]\n' "$(IFS=,$'\n'; echo "${json_entries[*]}")" > "$SUMMARY_FILE"
    echo "Summary written to $SUMMARY_FILE"
  fi
fi

echo "Cleaning repository artifacts..."
for path in "${repo_targets[@]}"; do
  remove_path "$path"
done
for path in "${terraform_local_targets[@]}"; do
  remove_path "$path"
done

if (( INCLUDE_HOME )); then
  if prompt "Also remove cached state under $HOME?"; then
    echo "Cleaning developer-home caches..."
    for path in "${home_targets[@]}"; do
      remove_path "$path"
    done
  fi
fi

echo "Uninstall complete. Run ./scripts/setup-all.sh to reinstall when ready."

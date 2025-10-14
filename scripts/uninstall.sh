#!/usr/bin/env bash
# Uninstall helper for the AI Dev Platform. It removes generated artifacts,
# caches, optional developer-home state, and (optionally) destroys Terraform
# managed infrastructure so the repository can be re-installed from a clean
# environment.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORCE=0
DRY_RUN=0
INCLUDE_HOME=0
DESTROY_TERRAFORM=0

usage() {
  cat <<'USAGE'
Usage: ./scripts/uninstall.sh [options]

Options:
  --force             Skip interactive confirmation.
  --dry-run           Show what would be removed without deleting anything.
  --include-home      Also remove Codex/Cursor caches under $HOME.
  --destroy-cloud     Run `terraform destroy` in infra/terraform/envs/*.
  -h, --help          Show this message.

Examples:
  ./scripts/uninstall.sh --dry-run
  ./scripts/uninstall.sh --include-home --destroy-cloud
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --include-home)
      INCLUDE_HOME=1
      shift
      ;;
    --destroy-cloud)
      DESTROY_TERRAFORM=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

cd "$ROOT_DIR"

if [[ ! -f "$ROOT_DIR/package.json" ]]; then
  echo "Error: script must be run from the repository root." >&2
  exit 1
fi

shopt -s nullglob

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

# Terraform local state within infra/terraform
repo_targets+=("$ROOT_DIR/infra/terraform/.terraform")
repo_targets+=("$ROOT_DIR/infra/terraform/.terraform.lock.hcl")
repo_targets+=("$ROOT_DIR/infra/terraform/terraform.tfstate")
repo_targets+=("$ROOT_DIR/infra/terraform/terraform.tfstate.backup")
repo_targets+=("$ROOT_DIR/infra/terraform/envs"/*/.terraform)
repo_targets+=("$ROOT_DIR/infra/terraform/envs"/*/.terraform.lock.hcl)
repo_targets+=("$ROOT_DIR/infra/terraform/envs"/*/terraform.tfstate)
repo_targets+=("$ROOT_DIR/infra/terraform/envs"/*/terraform.tfstate.backup)

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

confirm() {
  local prompt="$1"
  if (( FORCE )); then
    return 0
  fi
  read -r -p "$prompt [y/N] " reply
  case "$reply" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *) return 1 ;;
  esac
}

if ! confirm "This will remove generated artifacts from $ROOT_DIR. Proceed?"; then
  echo "Aborted."
  exit 0
fi

echo "Cleaning repository artifacts..."
for path in "${repo_targets[@]}"; do
  remove_path "$path"
  done

if (( INCLUDE_HOME )); then
  if confirm "Also remove cached state under $HOME?"; then
    echo "Cleaning developer-home caches..."
    for path in "${home_targets[@]}"; do
      remove_path "$path"
    done
  fi
fi

if (( DESTROY_TERRAFORM )); then
  if ! command -v terraform >/dev/null 2>&1; then
    echo "Terraform not installed; skipping cloud destruction." >&2
  else
    if confirm "Run terraform destroy in infra/terraform/envs/*?"; then
      for env_dir in "$ROOT_DIR"/infra/terraform/envs/*; do
        [[ -d "$env_dir" ]] || continue
        echo "Destroying Terraform environment: $env_dir"
        if (( DRY_RUN )); then
          continue
        fi
        pushd "$env_dir" >/dev/null
        terraform init -upgrade >/dev/null
        terraform destroy -auto-approve || {
          echo "Terraform destroy failed for $env_dir" >&2
        }
        popd >/dev/null
      done
    fi
  fi
fi

echo "Uninstall complete. Run ./scripts/setup-all.sh to reinstall when ready."

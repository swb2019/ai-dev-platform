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
 AI Dev Platform • Onboarding Assistant
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
finished, run `npm install -g infisical` or rebuild the container, then retry.
INFICLI
  return 1
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

  printf '\n[onboard] Step 4: Pulling development secrets with Infisical...\n'
  while true; do
    if infisical pull; then
      printf '[onboard] Secrets pulled successfully.\n'
      break
    fi
    prompt_enter "Resolve the Infisical pull error and press ENTER to retry: "
  done
}

confirm_cursor_setup() {
  cat <<'CURSORMESSAGE'

[onboard] Step 5: Configure Cursor IDE for autonomous operation.
- Enable "Auto-Run" in Cursor Settings.
- Sign into the Claude Code extension.
- Sign into the OpenAI Codex (ChatGPT) extension if available.
CURSORMESSAGE
  prompt_enter "Press ENTER once the Cursor IDE configuration is complete: "
}

collect_final_confirmation() {
  printf '\n[onboard] Step 6: Final confirmation.\n'
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
  confirm_cursor_setup
  collect_final_confirmation
  finalize
}

main "$@"

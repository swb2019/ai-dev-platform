# AI Dev Platform Onboarding

## Purpose

`scripts/onboard.sh` delivers a guided, single-command onboarding sequence for new contributors. It confirms that authentication, secrets, and IDE integrations are ready for autonomous workflows inside the dev container.

## Quick Start

1. Connect to the dev container. The first integrated terminal opens with the custom profile `bash (onboard)` and automatically launches the onboarding script.
2. Follow each interactive prompt until the script reports success and writes `.onboarding_complete` in the repository root.
3. To rerun the flow, delete `.onboarding_complete` and execute `bash scripts/onboard.sh`.

## Script Walkthrough

1. **Welcome.** Provides context for the onboarding steps.
2. **GitHub CLI Auth Check.** Runs `gh auth status` until authentication succeeds. Use `gh auth login` if prompted.
3. **Git Remote Verification.** Calls `git ls-remote origin HEAD` to verify SSH/HTTPS connectivity.
4. **Secrets Bootstrap (Infisical).** Executes `infisical login` and `infisical pull` to authenticate and download development secrets.
5. **Cursor IDE Configuration.** Reminds you to enable Auto-Run and sign into Claude Code / Codex extensions.
6. **Final Confirmation.** Records completion only after explicit confirmation.

## Git Authentication Troubleshooting

- **SSH URLs:**
  - Ensure your SSH key is loaded (`ssh-add -l`).
  - Confirm agent forwarding is enabled if connecting through another host (`ForwardAgent yes`).
  - Retest with `ssh -T git@github.com`.
- **HTTPS URLs:**
  - Run `gh auth setup-git` to configure credentials for HTTPS remotes.
  - Verify the credential helper with `git config --global credential.helper`.
  - GitHub personal access tokens must include `repo` scope.

If authentication continues to fail, the onboarding script re-displays:

```
CRITICAL ERROR: Git authentication failed. Ensure your SSH Agent is forwarded (if using SSH)
OR that 'gh auth setup-git' is configured (if using HTTPS). Refer to docs/ONBOARDING.md for troubleshooting.
```

Resolve the issue, then press ENTER to retry the check.

## Infisical Notes

- The dev container installs the Infisical CLI via `npm install -g infisical` during `post-create`.
- `infisical login` opens an interactive prompt (Browser, Device Code, or Service Token). Complete it in the same terminal.
- `infisical pull` writes decrypted secrets to the local environment according to your Infisical project settings. Re-run the command whenever secrets change.

## IDE Configuration Tips

- Cursor ➜ Settings ➜ `General ▸ Auto-Run` ➜ enable.
- Verify that Claude Code and OpenAI Codex extensions show an authenticated state.
- Additional terminal sessions can safely use the standard `bash` profile once onboarding is complete.

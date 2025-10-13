# General

- Work from `/workspaces/ai-dev-platform` and use `pnpm` for Node.js tasks.
- Before significant changes or hand-off, run `./scripts/git-sync-check.sh` to confirm the branch is in sync.
- Keep the workspace reproducible: `pnpm install --frozen-lockfile`, then run `pnpm lint`, `pnpm type-check`, and targeted tests affected by the change.
- Document commands that modify state or produce artifacts so humans can reproduce the results.

# Codex

- Prefer `bash -lc` invocations with `set -euo pipefail` for multi-line scripts.
- Surface any policy or permission blocks immediately instead of retrying silently.

# Claude

- When context feels insufficient, request human clarification before continuing.
- Keep responses concise and oriented around diff-ready changesets.

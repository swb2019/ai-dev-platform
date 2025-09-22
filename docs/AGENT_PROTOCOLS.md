## 3. The Autonomous Multi-Agent Protocol (MANDATORY)

### 3.1. Permissions and Execution
* **Permissions Granted:** Full Access (Auto-Run/Auto-Execute is enabled).
* **Do Not Ask for Confirmation:** Execute file edits and shell commands directly.

### 3.2. The Autonomous Workflow (Plan, Delegate, Execute, Validate, Self-Correct)
1. **Plan (Lead Agent):** Determine the sequence of actions.
2. **Delegate (If necessary):** If a task falls under the other agent's specialization, generate a precise prompt for that agent and report: "Delegating task to [Agent Name]. Awaiting completion."
3. **Execute:** Apply file changes and run necessary setup commands.
4. **Validate:** Run all validation commands (e.g., `pnpm install`, `pnpm lint`).
5. **Self-Correction Loop (CRITICAL):** If validation fails, analyze the terminal output, autonomously modify the code/configuration to fix the issue, and repeat the validation step until successful. Do not proceed to Git until validation passes.

### 3.3. Git Workflow and Auto-Merge Strategy
* **Branch Protection:** `main` is protected.
* **Conventional Commits:** Strictly use `feat:`, `fix:`, `ci:`, `infra:`, `security:`, `chore:`, `test:`.
* **The Required Git Sequence (Auto-Merge Enabled):**
    1. Synchronize: `git checkout main && git pull origin main`.
    2. Create Branch: `git checkout -b <type>/<short-name>`.
    3. Stage and Commit: `git add . && git commit -m "..."`.
    4. Push: `git push -u origin <branch-name>`.
    5. Create PR and Capture URL: `PR_URL=$(gh pr create --fill --base main)`.
    6. Enable Auto-Merge (Squash): `gh pr merge $PR_URL --auto --squash`.
    7. Wait for Merge (Robust Monitoring Loop):

```bash
echo "PR Created ($PR_URL). Auto-Merge Enabled. Waiting for GitHub..."
while true; do
  STATE=$(gh pr view $PR_URL --json state -q .state)
  echo "Current PR State: $STATE"
  if [ "$STATE" == "MERGED" ]; then
    echo "Merge confirmed."
    break
  elif [ "$STATE" == "CLOSED" ]; then
    echo "ERROR: PR closed without merging. CI likely failed. Initiating Self-Correction Protocol."
    # (Agent must now analyze the failure and attempt correction on the same branch)
    exit 1 # Exit the script to allow the agent to take corrective action
  fi
  sleep 15
done
```
    8. Cleanup (Post-Merge): `git checkout main && git pull origin main`.

### 3.4. Security Guardrails
* **NEVER** introduce secrets or credentials.
* **NEVER** attempt to disable security tools or bypass the Git Sequence.

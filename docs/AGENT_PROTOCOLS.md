# Agent Protocols

## Autonomous Execution Protocol

This document outlines the standardized protocols for autonomous AI agent operation within the AI Dev Platform environment.

### 3. Git Auto-Merge Strategy and Autonomous Workflow

**All code changes must follow this Git workflow sequence:**

#### 3.1. Branch Strategy

- **Main Branch Protection**: Direct commits to `main` are prohibited
- **Feature Branches**: All changes must be implemented on feature branches using the naming convention: `feat/feature-name`, `fix/bug-name`, `chore/task-name`
- **Branch Creation**: Create feature branches from the latest `main` branch

#### 3.2. Commit Standards

- **Conventional Commits**: Use conventional commit format: `type(scope): description`
- **Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
- **Security**: All commits must pass security scanning (Gitleaks, Semgrep)
- **Attribution**: Include Claude Code attribution in commit messages

#### 3.3. Git Sequence Protocol (Mandatory for All Changes)

**Step 1-2: Branch Creation and Development**

```bash
git checkout -b feat/feature-name
# Implement changes, commit locally
```

**Step 3: Push Branch**

```bash
git push -u origin feat/feature-name
```

**Step 4: Create Pull Request**

```bash
PR_URL=$(gh pr create --fill --base main --title "feat: descriptive title")
```

**Step 5: Enable Auto-Merge**

```bash
gh pr merge $PR_URL --auto --squash
```

**Step 6: Monitoring Loop**

```bash
while true; do
  STATE=$(gh pr view $PR_URL --json state -q .state)
  if [ "$STATE" = "MERGED" ]; then
    echo "PR merged successfully"
    break
  elif [ "$STATE" = "CLOSED" ]; then
    echo "PR closed - requires intervention"
    exit 1
  fi
  sleep 30
done
```

**Step 7: Self-Correction Protocol**

- If PR state becomes "CLOSED": Analyze failure, address issues, create new PR
- If checks fail: Fix issues on feature branch, push updates
- If conflicts occur: Rebase feature branch against latest main

**Step 8: Post-Merge Cleanup**

```bash
git checkout main
git pull origin main
git branch -d feat/feature-name
```

#### 3.4. Quality Gates

- **Pre-commit Hooks**: Automated linting, formatting, and security scanning
- **CI/CD Pipeline**: All checks must pass before merge
- **Required Status Checks**: Security scans, type checking, tests, build
- **Review Requirements**: Automated review and merge when all checks pass

#### 3.5. Security Requirements

- **Secret Detection**: Gitleaks scanning on all commits
- **Vulnerability Scanning**: Semgrep analysis for security issues
- **Dependency Scanning**: Automated dependency vulnerability checks
- **Code Quality**: ESLint with security-focused rules

### 4. Execution Standards

#### 4.1. Autonomous Operation

- Execute tasks without human intervention when protocols are clear
- Implement self-correction when standard errors occur
- Follow established patterns and conventions
- Maintain security-first approach in all operations

#### 4.2. Error Handling

- Retry transient failures with exponential backoff
- Log detailed error information for debugging
- Implement graceful degradation when possible
- Escalate to human intervention only when protocols fail

#### 4.3. Validation and Testing

- Run comprehensive tests before considering tasks complete
- Validate all security measures are functioning
- Ensure code quality standards are met
- Verify functionality against requirements

### 5. Communication Protocols

#### 5.1. Status Reporting

- Provide clear status updates on task progress
- Report completion with verification steps
- Document any deviations from standard protocols
- Include relevant URLs, commit hashes, and validation results

#### 5.2. Human Escalation

- Clearly identify when human intervention is required
- Provide context and attempted solutions
- Suggest specific actions for resolution
- Maintain detailed logs for troubleshooting

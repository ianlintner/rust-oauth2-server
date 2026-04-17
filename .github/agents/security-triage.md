# Security Finding — Copilot Agent Instructions

You have been assigned a security finding issue created by the caretaker security agent.

## Your task

1. **Read the issue carefully.** It contains:
   - The alert type (Dependabot, Code Scanning, or Secret Scanning)
   - Severity and affected package / rule
   - A direct link to the alert on GitHub
   - Suggested remediation steps

2. **Investigate the finding:**
   - Open the linked GitHub alert for full details.
   - Check whether the affected code path is reachable in production.

3. **Remediate:**
   - **Dependabot alerts**: Upgrade the vulnerable dependency. Update `pyproject.toml` (or equivalent), run `pip-compile` / `poetry lock`, open a PR.
   - **Code scanning (CodeQL) alerts**: Fix the flagged code pattern (e.g., SQL injection, XSS, unsafe deserialization). Add a regression test.
   - **Secret scanning alerts**: Immediately rotate the leaked credential. Remove all traces from git history using `git filter-repo`. Update secrets in GitHub Actions / environment config.

4. **Open a PR** with your fix. Reference the caretaker issue (`Closes #<number>`) in the PR description.

5. **If you believe the finding is a false positive:**
   - Add the label `security:false-positive` to the issue.
   - Leave a comment explaining why it is not exploitable (specific reason, code path analysis).
   - Caretaker will dismiss the underlying alert on the next run.

6. **Do NOT close the issue manually** — caretaker will close it once the fix PR is merged and the alert is resolved.

## Severity guide

| Severity | SLA                 |
| -------- | ------------------- |
| Critical | Fix within 24 h     |
| High     | Fix within 72 h     |
| Medium   | Fix within 1 week   |
| Low      | Fix within 1 sprint |

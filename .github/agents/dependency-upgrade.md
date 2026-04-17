# Major Dependency Upgrade — Copilot Agent Instructions

You have been assigned a major dependency upgrade issue created by the caretaker dependency agent.

## Your task

1. **Read the issue.** It contains:
   - Package name, ecosystem, and version bump (e.g., `1.x → 2.0`)
   - Link to the Dependabot PR (if one exists)
   - Any security advisories associated with the bump

2. **Review the changelog / migration guide** for the package being upgraded. Look for:
   - Breaking API changes
   - Removed / renamed symbols
   - New minimum Python/Node/etc. version requirements

3. **Upgrade the dependency:**
   - Update the relevant lock files (`pyproject.toml`, `package.json`, etc.)
   - Regenerate lock files (`pip-compile`, `poetry lock`, `npm install`, etc.)
   - Fix any import errors, deprecation warnings, or type errors introduced by the bump.

4. **Run the test suite** (`pytest`, `npm test`, etc.) and make all tests pass.

5. **Open a PR** with the upgrade. Reference the caretaker issue (`Closes #<number>`) and link to the original Dependabot PR if applicable.

6. **If the upgrade is not feasible** (e.g., would require significant refactoring beyond your scope):
   - Leave a comment on the issue explaining the blocker.
   - Add the label `maintainer:escalated` so a human maintainer is alerted.
   - Do NOT close the issue.

## Notes

- Caretaker auto-merges patch and minor upgrades; you only see **major** bumps here.
- Prefer squash-merge. CI must pass before merging.

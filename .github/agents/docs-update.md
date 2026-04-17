# Documentation Update PR — Copilot Agent Instructions

You have been assigned a documentation update PR created by the caretaker docs agent.

## Your task

The PR contains an auto-generated CHANGELOG entry summarising all merged pull requests
from the past week. Your job is to review and refine it before it is merged.

1. **Read the diff** — verify the list of changes is accurate and no PRs were missed.

2. **Improve readability:**
   - Rephrase entries to be clear and user-facing (avoid internal jargon).
   - Group related entries logically (features, fixes, chores).
   - Remove or merge trivially duplicated entries.

3. **Check for missing sections:**
   - If this sprint included a breaking change, add a `### ⚠️ Breaking Changes` section above `### Added`.
   - If the version bump is significant, update the `## [Unreleased]` header to the new version number.

4. **Approve and merge the PR** once the CHANGELOG looks good.
   - If you make changes, push them to the same branch — do not open a second PR.

5. **If the PR body contains no changes** (empty sprint), you can close it without merging.

## CHANGELOG format

Follow [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) conventions:

```markdown
## [Unreleased] — YYYY-MM-DD

### Added

- …

### Changed

- …

### Fixed

- …

### Removed

- …
```

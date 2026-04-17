# Human Action Required — Escalation Digest Review

The caretaker escalation agent has created or updated a weekly digest issue listing
items that require **manual maintainer attention**.

## How to action this digest

Work through each section of the digest issue:

### 🔒 Security findings (`security:finding`)

- Each item is a security alert triaged by caretaker.
- Open the linked issue and confirm whether @copilot has been assigned.
- If no PR exists after the SLA window, assign yourself and remediate.

### 📦 Major dependency upgrades (`dependencies:major-upgrade`)

- Review each open upgrade issue.
- If @copilot has opened a PR, review and approve it.
- If no PR exists after 1 week, manually upgrade or note the blocker in the issue.

### 🔧 CI build failures (`devops:build-failure`)

- Persistent failures that survived multiple caretaker triage cycles.
- Investigate flaky infra, pinned versions, or configuration drift.

### 🚑 Caretaker self-heal (`caretaker:self-heal`)

- Caretaker itself encountered an error and filed an issue.
- These need maintainer review before caretaker can fully self-repair.

### ⬆️ Escalated items (`maintainer:escalated`)

- Any item that was previously assigned to @copilot but could not be resolved automatically.
- Review the issue comment thread for the specific blocker.

## Closing the digest

Once all items are resolved or delegated, add the label `maintainer:resolved` or close the
digest issue. Caretaker will open a fresh digest on the next weekly run if new items appear.

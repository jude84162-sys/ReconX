## Summary & Intent

<!-- Briefly describe WHAT this PR changes and WHY. Link any related issues (#XX). -->

## Risk Tier & Target Impact

Please select the appropriate Risk Tier for this change:

- [ ] **Tier 1 (Low Risk):** Docs, unit test additions, typo fixes, non-breaking site module additions.
- [ ] **Tier 2 (Medium Risk):** Refactoring CLI logic, dependency bumps, adding core modules/features.
- [ ] **Tier 3 (High Risk):** Touches network/TLS handling, crypto, authentication/auth checks, breaking API/CLI changes, core engine rewrites.

---

## Author Self-Review Checklist

- [ ] **Fast Triage Verification:**
  - [ ] Code does exactly what the description claims.
  - [ ] No hardcoded secrets, API tokens, or unintended debugging credentials.
  - [ ] No unbounded loops or missing request timeouts on network paths.
  - [ ] Included tests that fail *without* this change.
  - [ ] Handled `null`, empty, or unexpected network error responses gracefully.
  - [ ] Verified backward compatibility for CLI flags and core APIs.
- [ ] **Testing:**
  - Unit tests run and pass (`pytest`)
  - Integration/offline network mocks verified

---

## Rollout / Rollback

<!-- How does this reach users, and how do we undo it? Required for Tier 3. -->

---

## Unsure / Areas Needing Special Review

<!-- Is there any part of this diff you are unsure about or want reviewers to scrutinize? (e.g. edge cases, async performance, error handling) -->

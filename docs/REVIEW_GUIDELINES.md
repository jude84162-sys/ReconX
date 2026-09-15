# ReconX Code Review Guidelines

This document outlines our process for conducting code reviews across the ReconX project.

---

## ⚡ Fast Triage (Tier 1 & Tier 2)

When reviewing PRs under time constraints, focus on these 7 questions to catch the majority of critical defects:

1. **Intent:** Does the PR actually do what the description claims?
2. **Security:** Are there command injections, unhandled external inputs, or hardcoded secrets in the diff?
3. **Performance:** Are there unbounded loops, un-throttled async calls, or missing timeouts in hot execution paths?
4. **Validation:** Is there a test that explicitly fails without this fix?
5. **Resilience:** Are `null`, empty, timeout, or HTTP error responses handled gracefully?
6. **Compatibility:** Does this introduce breaking changes to the CLI, API signatures, or default options?
7. **Production Confidence:** Would you be comfortable being alerted for a failure caused by this change at 3 AM?

---

## 🚨 Stop & Escalate Protocol

Immediately block merging and seek a second reviewer or explicit mitigation if any of the following apply:

* **Authentication & Cryptography:** Any modifications touching auth headers, token parsing, or cryptographically sensitive routines **must** be approved by a second core maintainer.
* **Network & Security Relaxations:** Disabling SSL verification (`verify=False`), overriding standard security headers, or bypassing rate limits requires explicit written justification in the PR description.
* **Destructive or Irreversible Operations:** Any recursive delete, overwrite, or migration that cannot be trivially undone must name the exact paths/targets it affects, and must not fall back to sweeping broad default locations.
* **Unbounded PR Size:** If a PR is too large to trace effectively, request the author to split it into logical chunks. **Do not approve based on trust.**
* **Untestable Code:** If a change is fundamentally untestable, treat it as an architectural flaw and discuss redesigning before merging.

---

## 🔍 Full Pull Request Review Checklist

### 1. Correctness & Business Logic

- [ ] Functional requirements match issue description.
- [ ] Logic branches, loops, and edge cases are sound.
- [ ] Output formatting (JSON, CSV, TXT) matches the established schemas.

### 2. Security

- [ ] Input sanitization on user-supplied usernames, domains, and IPs.
- [ ] Zero committed credentials or API keys.
- [ ] Safe subprocess calls (no raw shell invocation on unsanitized strings).
- [ ] Secrets are redacted before they reach logs or error messages.

### 3. Performance & Networking

- [ ] Bounded concurrency (thread pools / semaphore limits enforced).
- [ ] Explicit HTTP connection and read timeouts set.
- [ ] Context managers used for socket/file resource management.

### 4. Tests & Error Handling

- [ ] Network calls properly mocked with the standard library (`unittest.mock`), matching the existing `tests/` conventions.
- [ ] Meaningful error messages returned to user instead of raw stack traces on expected network errors.

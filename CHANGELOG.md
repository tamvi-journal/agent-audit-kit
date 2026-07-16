# Changelog

## 0.2.0

- Add shared contract version `1.0` and versioned result serialization.
- Accept mapping-shaped worker packets through the Python API.
- Enforce trusted envelope identity and detect packet identity mismatch.
- Require nonblank string verifier identities and inspectable artifact locators.
- Prevent disabled verification from granting release eligibility.
- Add sensitive capability preflight flags for shell, network, external mutation, money touching, and completion authority.
- Fail closed on malformed policy mappings, conflicting identities, and invalid or blank candidate content.
- Add dependency-free JSON CLI and stable exit codes.
- Add opt-in built-in guards, typing marker, CI, and shared-agent integration docs.
- Change the distribution name to `tamvi-agent-gate` while preserving the `agent_audit_kit` import namespace.

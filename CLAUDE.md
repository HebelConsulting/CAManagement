# CLAUDE.md

Guidance for AI assistants working in this repository.

## Documentation

- **Always keep the top-level `README.md` current.** After any change that adds,
  removes or alters a CLI command/option, a project, a build/publish step, or a
  user-facing behaviour or caveat, update `README.md` in the same change if it is
  now outdated or incomplete. The README is the project's front door; treat it as
  part of the deliverable, not an afterthought.
- `SPEC.md` records design decisions, rationale and verification status — update
  it when a decision is made or a capability is verified.

## Conventions (already in force across the codebase)

- String interpolation over `+` concatenation; prefer `switch` expressions.
- Write tests alongside the implementation; the suite must stay green
  (`dotnet test CAManagement.sln`).
- Do not make architectural decisions without prior consent — surface options
  and wait.
- Be explicit about limitations: state caveats plainly rather than hiding them.
- **No squash merges.** A pull request lands with its individual commits intact
  (merge commit or rebase-merge, never squash) — the commits are part of the
  record, and flattening them discards it. Enforced in the repository settings
  (squash merging is disabled), so the wrong button does not exist.

## Layout

`src/` holds the projects: `CAManagement.Pkcs11` (+ `.Signing`) — PKCS#11 interop
(multi-targets `net10.0` and `net10.0-windows`); `CAManagement.X509` — DER/X.509
authoring and the analyzer; `CAManagement.Cli` — the `caconsole` tool;
`CAManagement.Tests`. Integration tests need SoftHSM2.

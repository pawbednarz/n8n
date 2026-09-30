# Audit scope

## Repository state (facts)

- Repo: local clone of `pawbednarz/n8n` (fork of `n8n-io/n8n`).
- Branch: `claude/eloquent-einstein-jffi3d`.
- HEAD: `5933694096c78218c9a20be1fc89096fb8d872ad` ("ci: Let a preview instance take environment from a webhook (#38894)", 2026-09-17).
- Working tree: clean at audit start.
- Clone is shallow: only 50 commits of history are present. This limits `git log`/`git blame` based analysis (Stage 6 fix-history checks).
- Component versions (from package.json):
  - `n8n` (packages/cli) 2.40.0
  - `n8n-core` 2.40.0
  - `n8n-workflow` 2.40.0
  - `n8n-nodes-base` 2.40.0
  - `@n8n/n8n-nodes-langchain` 2.40.0
  - `@n8n/permissions` 0.77.0
  - `@n8n/db` 1.40.0
  - `@n8n/task-runner` 2.40.0
  - `@n8n/instance-ai` 1.25.0
  - `@n8n/config` 2.38.0
- Runtime: Node v22.22.2, pnpm 12.3.4.

## Audit scope (this review)

Defensive source review of the local repository only. No testing against any
live n8n instance (local or remote). No real credentials. No weaponized
exploits, exfiltration mechanisms, or off-lab attack chains. Verification is
by call-path reading plus isolated local property tests on synthetic data,
demonstrating only that a control fails.

Priority surfaces (per task): trust boundaries between `packages/cli`,
`packages/core`, `packages/workflow`, `packages/nodes-base`, and the
AI/LangChain packages; RBAC / multi-tenancy (projects, sharing, ownership);
credential use-vs-read separation; identity propagation into async execution;
import/export path handling; derived data (logs, execution results, telemetry)
redaction.

## Bug-bounty program scope — LIMITATION (not verified)

The official program page
(`https://n8n.notion.site/n8n-vulnerability-disclosure-program`, linked from
`SECURITY.md`) and the n8n.io / blog.n8n.io policy pages are **blocked by this
environment's network egress policy**. I therefore **cannot quote the current,
authoritative program rules** (in-scope assets/versions, excluded classes, PoC
and report requirements, self-hosted vs cloud split, reward tiers).

Per the task's quality rules, I do not assume program scope from memory. The
items below are widely-standard VDP conventions stated as **working assumptions
only**, to be confirmed against the real policy before any submission:

- **Assumption A1 (by-design code execution):** A user who already holds
  workflow create/edit permission can run code via the Code node / expressions
  by design. Such execution *as the acting user's own privilege level* is
  typically **out of scope**, UNLESS it crosses a trust boundary (sandbox
  escape beyond the documented capability, privilege escalation, cross-tenant
  reach, or reading data the actor should not have). This distinction is the
  crux of many n8n reports and is treated carefully below.
- **Assumption A2 (self-XSS / admin-attacks-own-instance):** Typically out of
  scope.
- **Assumption A3 (self-hosted vs cloud):** Some surfaces exist only in one
  model. Where a finding depends on deployment model, that dependency is
  recorded explicitly in the finding.
- **Assumption A4 (community/third-party nodes):** Third-party community node
  code is typically out of scope; built-in `nodes-base` and
  `nodes-langchain` are in scope.

If these assumptions turn out wrong once the policy is readable, affected
findings must be re-triaged.

## Environment limitations

- No egress to n8n.io, blog.n8n.io, notion.site, github.com advisory pages,
  nvd.nist.gov, osv.dev (all blocked). WebSearch (result snippets) works, but
  I will not use it to collect exploit/attack detail; Stage 6 is limited to a
  narrow "does an upstream fix already exist" check where reachable.
- Shallow clone (see above) limits fix-history / regression-commit analysis.
- No live instance: dynamic checks are limited to package-local unit/property
  tests run with the repo's own tooling.

# Next steps — prioritized open work

State at handoff: authorization core + ~16 high-value flows reviewed and found
hardened or by-design (`coverage.md` C1–C15, `hypotheses.md` H1–H10). No
category-(a) finding. The items below are the unreviewed high-value surfaces,
ordered by expected yield × severity. Each says what to read and what would
constitute a finding, so a next session does not repeat the completed analysis.

## N0 — Finish/submit F-1 (Source Control repositoryUrl RCE) — TOP PRIORITY
- Confirm program scope treats authenticated/privileged-scope RCE as in-scope,
  and dedup against GitHub Security Advisories / CVE (blocked in this env) — a
  fix may already exist upstream since promotions.ee/Git node were hardened.
- If a live instance is available, confirm end-to-end in a lab with a benign
  marker command (never exfiltration/destruction), to move the `ext::` execution
  from hypothesis to observed.
- Also probe the SSH path variants (`ssh -oProxyCommand=…` via a crafted remote)
  and the `updatePreferences`/reconnect paths, and whether `git pull`/scheduled
  sync re-triggers on a stored malicious URL after restart.
- Draft fix + regression test are in `findings.md` F-1 / `report-draft.md`.

## N1 — AI-node transport injection completeness (low)
- Why: F-B1 refuted direct HTTP clients in built-in nodes, but did not confirm
  every AI node *passes* the injected `OutboundHttp` transport to its SDK on
  every path (streaming vs non-streaming, custom base URL).
- Read: each `packages/@n8n/nodes-langchain/nodes/llms/*` node + `microsoft-utils`
  / OpenAI assistant op; confirm the dispatcher/fetch/egress filter reaches the
  SDK call.
- Finding if: a path constructs an SDK client without the transport → SSRF bypass
  when protection enabled (category (a) for Cloud/enabled).

## N2 — Webhook + Form trigger unauthenticated surface (HIGH yield/severity)
- Why: recent n8n CVE cluster lived here (form/webhook expression handling,
  content-type handling). Not reviewed beyond route mapping.
- Read: `packages/cli/src/webhooks/*` (routing, `WebhookService`, live vs test
  webhook resolution), form-trigger node param resolution, `Respond to Webhook`,
  how request body/headers/query flow into expression evaluation, and any
  file/multipart handling.
- Finding if: an unauthenticated request causes expression evaluation on
  attacker-controlled input beyond intended templating, cross-workflow/tenant
  path resolution, or a file read/write. (Confirm against patched CVEs — do not
  re-report fixed issues; check the fix is actually present at 2.40.0.)
- Note: stay at call-path/PoC-on-synthetic-data level; do not build a working
  RCE.

## N3 — Execution data redaction completeness (medium)
- Why: I6 derived-data. A redaction subsystem exists keyed on per-node
  `sensitiveOutputFields` + `redactionInfo`
  (`executions/execution-redaction*.ts`, `execution-redaction-proxy.service.ts`).
  Completeness not audited.
- Read: the redaction strategies, where `processExecution(s)` is invoked on the
  read path (`execution.service*.ts`, enterprise variant), and whether pinned
  data / binary refs / error objects / sub-execution data are covered.
- Finding if: a `workflow:read`-only user retrieves an execution containing
  another principal's secret that should have been redacted, OR a node that
  declares no `sensitiveOutputFields` leaks credential material it received.
  (Weigh against A1: workflow data visible to workflow readers is often
  by-design.)

## N4 — Queue/scaling execution identity (medium)
- Why: I4 — identity/permission context across main→worker in queue mode.
- Read: `packages/cli/src/scaling/*`, how a job carries the initiating user /
  project, `workflow-runner.ts`, `workflow-execute-additional-data.ts`
  (`getBase`), and how credentials are resolved worker-side.
- Finding if: a worker resolves credentials or executes with authority not tied
  to the workflow's owning project, or a job payload lets one tenant's execution
  read another's data.

## N5 — Auth/session + SSO + oauth-server + token-exchange (medium)
- Read: `auth/auth.service.ts` (JWT issue/verify, cookie, browserId binding),
  MFA enforcement edges, password-reset/invite/change-email token entropy &
  single-use, `modules/sso-*`, `modules/oauth-server`,
  `modules/token-exchange` (`embed-auth`).
- Finding if: token forgery/replay, MFA bypass, an unauth SSO/oauth route
  reaching authenticated function, or predictable/reusable reset tokens.

## N6 — Task runner boundary (high severity, careful scope)
- Read: `packages/@n8n/task-runner*` broker auth (grant token), what the runner
  can reach in the main process, Python (Pyodide) vs JS isolation contract.
- Finding if: the broker accepts unauthenticated task submission, or the runner
  reaches secrets/other tenants beyond its contract. NOTE: Code-node code
  execution by an authorized author is by-design (A1); only a boundary escape
  qualifies. Do NOT weaponize a sandbox escape — describe at call-path level.

## N7 — dynamic-credentials.ee resolver internals (low/medium)
- Read: the resolver token storage keying, `validateIdentity`, csrf-state
  binding, and whether the unauth authorize/revoke endpoints can act on another
  caller's stored token.
- Finding if: a caller can authorize/revoke or read a token bound to a different
  identity.

## Environment blockers to lift for a fuller audit
- Network egress to advisory sources (GitHub Advisories, NVD, OSV) and n8n.io /
  the VDP page is blocked → Stage 0 program scope and Stage 6 dedup are
  unverified. Have the user confirm current program scope/exclusions and, if a
  finding is confirmed, run dedup before submission.
- Shallow clone (50 commits) → no fix-history/`git blame` analysis.
- No running instance → dynamic verification limited to package-local tests.

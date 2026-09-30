# Findings

Categories (per task): **(a)** bug-bounty vulnerability — a violated trust
boundary with real impact; **(b)** hardening / defense-in-depth; **(c)** by-design.
Only (a) belongs in `report-draft.md`.

## Category (a) — confirmed bug-bounty vulnerabilities

**None confirmed** in the surfaces reviewed at commit `5933694` (n8n 2.40.0).

This is a genuine negative result over the crown-jewel authorization surfaces
(RBAC core, credential use/read/decrypt, resource IDOR on binary-data /
executions / package export-import, design-time credential use in loadOptions,
public-API vs internal-API parity). See `coverage.md` C1–C15 and the refuted
hypotheses H1–H9 in `hypotheses.md`, each with the specific control cited. It is
**not** a statement that the product is free of vulnerabilities: large,
high-severity surfaces remain unreviewed (see `coverage.md` gaps and
`next-steps.md`), and the expression sandbox / task-runner classes were
deliberately not probed for escapes (weaponization is out of scope for this
engagement).

## Category (c) — by-design (documented, not a report item)

### F-C1 — SSRF protection is opt-in (off by default) on self-hosted
- Commit/loc: `@n8n/config/src/configs/ssrf-protection.config.ts:92`
  (`enabled = false`); enforced in
  `@n8n/backend-network/src/http/outbound-http.ts:261` (`resolveSsrf` →
  `'disabled'` when `!enabled`).
- Behaviour: with protection off, node HTTP requests (HTTP Request node, URL
  import, OAuth/discovery) can reach private/loopback/link-local/cloud-metadata
  addresses. The engine that would block them is correct and complete when
  enabled (connect-time secure DNS lookup defeats TOCTOU/rebinding;
  redirects re-checked; IP-literals and IPv6 handled;
  `169.254.0.0/16` in the default blocklist).
- Why (c): explicitly documented as intentional
  (config comment: "Off by default so existing self-hosted setups that call
  internal services keep working"), consistent with n8n's stated principle that
  security must not break the common building experience. An authenticated
  workflow author making outbound HTTP is intended functionality; SSRF hardening
  is an operator opt-in (`N8N_SSRF_PROTECTION_ENABLED=true`, presumably set on
  n8n Cloud).
- Caveat: this rests on scope assumption A1/A3 (`scope.md`) and on Cloud
  enabling it. If the bug-bounty program treats "reaching internal resources on
  Cloud" as in-scope, then the relevant question is a *bypass while enabled*
  (F-B1), not this default.

## Category (b) — hardening / defense-in-depth (documented, not a report item)

### F-B1 — SSRF bypass via nodes using a direct HTTP client — LARGELY REFUTED
- Hypothesis: a node that imports `axios`/`got`/`node-fetch`/`http` directly,
  instead of the `OutboundHttp`/request-helper pipeline, would not run the SSRF
  guard even when `N8N_SSRF_PROTECTION_ENABLED=true`.
- Evidence checked:
  - `packages/nodes-base/nodes`: **no** direct `axios`/`got`/`node-fetch`/
    `undici` imports. Only `nodes/Kafka/utils.ts` imports `https` — for a Kafka
    schema-registry agent whose host comes from credential config, not a
    per-request user URL (different threat model; internal brokers expected).
  - `packages/@n8n/nodes-langchain/nodes`: no direct HTTP-client imports; AI
    nodes thread the guard via `getSecureEgressFilter` / `useDefaultSsrfPolicy` /
    `OutboundHttp` transport injection (OpenAI, Azure, Mistral, xAI, OpenRouter,
    Nvidia, Moonshot, Minimax, Lemonade, Microsoft, …).
- Status: refuted for the built-in node packages — the outbound surface
  consistently routes through `OutboundHttp`, so the enabled SSRF policy applies.
  Residual (low-priority) gap: confirming each AI node actually *passes* the
  injected transport to its SDK on every code path (spot-checked, not exhaustive)
  — `next-steps.md` N1.
- Note: `getNodeAgent()` intentionally does not validate targets itself; it
  relies on the connect-time secure lookup and on callers validating
  (`outbound-http.ts` doc).

### F-B2 — Credential export decrypts on `credential:read` (expression values only)
- Loc: `modules/n8n-packages/entities/credential/credential.exporter.ts:50-72`.
- Observation: export fetches with `['credential:read']` then calls
  `Credentials.getData()` (raw decrypt) and keeps only expression-typed strings
  (`credential-export-policy.ts:filterValue`). The normal API reserves decrypt
  for `credential:update` and always redacts. Here a `credential:read`-only user
  (who also has `workflow:export` on a referencing workflow) can obtain the
  *expression* field values of a credential (e.g. `={{$env.X}}`,
  `=Bearer {{$json.t}}`), which the normal read path would mask.
- Why (b) not (a): expression values are references/templates, not the stored
  secret; raw secret strings and `oauthTokenData` are filtered out. Impact is
  disclosure of credential *structure/expressions*, not secrets. Worth aligning
  with the read/decrypt scope model, but no secret crosses the boundary.
- Suggested regression test: export a credential whose field is a literal secret
  vs. an expression; assert only the expression travels and the literal never
  does (locks in `filterValue` behaviour).

### F-B3 — `combineScopes` never masks global scopes
- Loc: `@n8n/permissions/src/utilities/combine-scopes.ee.ts:21-28`.
- Observation: the `sharing` mask filters `project` and `resource` scopes but not
  `global`. Correct today (global roles are instance-wide by design), but it is
  an implicit contract: if a future global role carried a resource-ish scope
  meant to be shareable, the mask would not constrain it. Documentation/tests
  should pin the intent.
- Why (b): no current violation; defense-in-depth/clarity only.

## Notes on excluded classes
- Authenticated code execution at the actor's own privilege (Code node,
  expressions) is treated as by-design per A1 and was not pursued as a finding.
- Expression sandbox escapes and task-runner escapes are high-severity but were
  not probed (no weaponization); they are the single most-audited external
  surface. Flagged as gaps, not findings.

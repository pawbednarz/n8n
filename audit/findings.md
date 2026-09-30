# Findings

Categories (per task): **(a)** bug-bounty vulnerability — a violated trust
boundary with real impact; **(b)** hardening / defense-in-depth; **(c)** by-design.
Only (a) belongs in `report-draft.md`.

## Category (a) — confirmed bug-bounty vulnerabilities

### F-1 — Source Control: unvalidated `repositoryUrl` → OS command execution via git `ext::` transport
- **Status:** CONFIRMED at code level (call path fully read). RCE not detonated
  (weaponization out of scope); a safe PoC proves the validation gap.
- **Commit / locations:**
  - `packages/cli/src/modules/source-control.ee/types/source-control-preferences.ts:13-14`
    — `repositoryUrl` is only `@IsString()` (no format/protocol validation).
  - `packages/cli/src/modules/source-control.ee/source-control-preferences.service.ee.ts:259-276`
    — `validateSourceControlPreferences` runs class-validator only (so only the
    `@IsString()` above).
  - `packages/cli/src/modules/source-control.ee/source-control.controller.ee.ts:66-129`
    — `POST /rest/source-control/preferences` (`@GlobalScope('sourceControl:manage')`),
    `initRepo` defaults to `true`.
  - `packages/cli/src/modules/source-control.ee/source-control-git.service.ee.ts:225,241,263`
    — `git.addRemote(SOURCE_CONTROL_ORIGIN, repositoryUrl)` then
    `trackRemoteIfReady` → `fetch()` (network op against the attacker-set remote).
  - `.../source-control-git.service.ee.ts:120-159` — git env sets
    `GIT_TERMINAL_PROMPT=0` etc. but **no** `GIT_ALLOW_PROTOCOL` restriction.
- **Violated rule / boundary (I8/I9 + RBAC intent):** the `sourceControl:manage`
  scope is intended to configure a git remote for environment sync, not to grant
  arbitrary host OS command execution. A principal holding only that scope can
  escalate to RCE on the n8n host.
- **Expected vs observed:** Expected — the remote URL is validated to an
  `http(s)`/`ssh` remote and transport helpers / argument-injection are rejected
  (this is exactly what the sibling `promotions.ee` module and the Git node do,
  see "Intended defense exists"). Observed — any string is accepted and handed to
  git; a value like `ext::sh -c '<cmd>'` makes `git fetch` invoke git's `ext`
  transport, which executes `<cmd>` on the host. A leading `-` also enables git
  argument injection.
- **Intended defense exists (proves this is a gap, not by-design):**
  - `packages/cli/src/modules/promotions.ee/promotions-git.service.ts:104-131`
    `validateSshRemoteUrl`: `if (remoteUrl.startsWith('-') || remoteUrl.includes('::')) throw` —
    comment: "Git transport helpers and local paths can execute or expose host
    data." Plus `validateHttpRemoteUrl` enforcing `http:`/`https:`.
  - `packages/nodes-base/nodes/Git/Git.node.ts:635` sets
    `GIT_ALLOW_PROTOCOL` (excludes `ext`/`fd`), tested at
    `Git.node.test.ts:1603` with `ext::sh -c "id"` / `fd::17/foo`.
  - Source-control.ee has neither → the inconsistency is the bug.
- **Trust boundary / who can reach it (nuance, stated honestly):**
  - `sourceControl:manage` is in `GLOBAL_OWNER_SCOPES` and
    `GLOBAL_ADMIN_SCOPES` (= owner scopes) and is an assignable **custom-role**
    scope, bundled in `GLOBAL_CUSTOM_ROLE_SCOPE_GROUPS.settings.Manage`
    (`@n8n/permissions/.../global-scopes.ee.ts:63,192`,
    `custom-role-scopes.ee.ts:90`).
  - **Owner:** self-compromise → out of scope (A2).
  - **Default admin:** already has `communityPackage:install` (npm postinstall =
    host RCE by design), so for a *default* admin this overlaps an existing
    capability → weaker as an escalation.
  - **Custom role with the settings-"Manage" bundle but not
    `communityPackage:install`:** genuine escalation — a non-owner/non-admin
    "instance-settings manager" gains host RCE they were not meant to have. This
    is the category-(a) case.
  - Enterprise-gated (source control + custom RBAC are licensed features).
- **Impact (fact vs inference):** Fact — arbitrary host process execution as the
  n8n process user on `fetch`. Inference — full instance compromise: read the
  encryption key and all credentials, all projects/tenants' data; on n8n Cloud,
  compromise of the tenant container (cross-tenant/platform impact depends on
  Cloud isolation, which I cannot verify here).
- **Safe verification:** `audit/poc/f1-repo-url-validation-gap.mjs` (run with
  `node`, no deps, no git executed) demonstrates the differential: `ext::sh -c …`,
  `fd::17/foo`, `-oProxyCommand=…`, and `file:///…` are all ACCEPTED by
  source-control's effective validation (`@IsString()` only) but REJECTED by the
  promotions `validateRemoteUrl`. Result: 4/4 malicious forms accepted by
  source-control, rejected by promotions; legitimate `https://…/repo.git` and
  `git@host:owner/repo.git` accepted by both. **Limitation:** `node_modules` is
  empty in this container, so the real modules could not be imported/executed;
  the PoC mirrors the cited source verbatim. The `@IsString()`-only check is
  quoted directly from the source, so the source-control "ACCEPT" side is exact.
- **Recommended fix:** validate `repositoryUrl` before persisting/using it —
  reuse the promotions rule (reject control chars, leading `-`, `::`; require
  `http:`/`https:` or an `ssh://`/scp-like remote; reject inline credentials)
  and/or set `GIT_ALLOW_PROTOCOL` on the git env as the Git node does. Prefer a
  shared helper so all three git call sites converge.
- **Regression test:** a test asserting `validateSourceControlPreferences`
  rejects `ext::`, `fd::`, `file://`, leading-`-`, and control-char URLs, and
  accepts normal `https://…/repo.git` and `git@host:owner/repo.git`.
- **Dedup:** advisory sources unreachable in this env (egress blocked) → novelty
  UNVERIFIED. The vector is a known class; n8n fixed it in `promotions.ee` and
  the Git node, so a source-control.ee advisory/fix may exist upstream — must be
  checked before submission.

---

## Category (a) — other surfaces reviewed

Beyond F-1, the crown-jewel authorization surfaces reviewed (RBAC core,
credential use/read/decrypt, resource IDOR on binary-data / executions /
package export-import, design-time credential use in loadOptions, public-API vs
internal-API parity, waiting-webhook resume tokens, data-table SQL, community
npm exec, AI/chat markdown XSS) produced **no additional confirmed finding**.
See `coverage.md` and refuted hypotheses H1–H10 in `hypotheses.md`, each with the
specific control cited. This is not a claim the product is vulnerability-free:
unreviewed high-value surfaces remain (see `next-steps.md`), and the expression
sandbox / task-runner escape classes were deliberately not probed
(weaponization out of scope).

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

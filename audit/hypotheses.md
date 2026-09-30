# Hypotheses — evidence and counter-evidence

Status key: REFUTED (control found), BY-DESIGN, OPEN (needs more work).
Each is deduplicated by root cause + trust boundary, not by symptom.

## H1 — Connect-only users can read credential secrets via getOne — REFUTED
- Rule (I2): use/connect must not reveal secret values.
- Path: `getOneForUser` (`credentials.service.ee.ts:103`) decrypts for a
  resolvable credential when the user has `credential:connect`.
- Counter-evidence: it calls `credentialsService.decrypt(credential)` with
  default `includeRawData=false`, which `redact()`s secret-typed fields
  (`credentials.service.ts:956,1380`). Only a redacted blueprint + oauth
  connected-flag is returned. Secrets stay `***`.
- Verdict: control present. Not a finding.

## H2 — `includeData` on credential list leaks secrets to non-owners — REFUTED
- Path: `GET /credentials?includeData=true` → `getMany`.
- Counter-evidence: `addDecryptedDataToCredentials` decrypts only rows where
  `c.scopes.includes('credential:update')` and via `decrypt()` (redacted).
  Member list is filtered by a sharing subquery on `credential:read` roles;
  personal-project access blocked unless owner or global `credential:read`.
- Verdict: not a finding.

## H3 — Binary-data endpoint IDOR / path traversal across tenants — REFUTED
- Rule (I5/I7): a user reads only binaries of executions they can access.
- Counter-evidence: `binary-data.controller.validateBinaryDataId` rejects `..`
  (both separators); `BinaryDataAccessService.hasReadAccess` resolves the owning
  execution/workflow and checks `workflow:read` via `getSharedWorkflowIds`;
  `database` mode with `TEMP_EXECUTION_ID` → denied. FS store also rejects `..`.
- Verdict: not a finding.

## H4 — Package export lets a user export workflows/credentials they cannot access (IDOR) — REFUTED
- Rule (I1): export scoped to the caller's own resources.
- Counter-evidence: `WorkflowExporter` uses
  `findWorkflowsByIdsForUser(ids, user, ['workflow:export'])` +
  `assertEveryRequestedEntityAccessible`; transitive
  `WorkflowDependencyResolver` re-checks each hop with the same finder and skips
  inaccessible ids (kept only as unresolved requirements); `CredentialExporter`
  fetches with `findCredentialForUser(id, user, ['credential:read'])` and exports
  nothing for inaccessible credentials.
- Verdict: not a finding.

## H5 — Package import binds a workflow to a credential the importer cannot use (credential-use escalation) — REFUTED
- Rule (I1/I3): imported workflow can only reference credentials usable by the
  importing user in the target project.
- Counter-evidence: `CredentialMatcher.match` resolves both explicit bindings and
  id-based matches only against `getCredentialsAUserCanUseInAWorkflow(user,
  {projectId})`; a reference to an unusable id becomes a `not_found` stub, not a
  binding; type must also match.
- Verdict: not a finding.

## H6 — Package import tar extraction allows arbitrary file write / zip-slip — REFUTED
- Counter-evidence: `TarPackageReader` extracts to an in-memory Map, never to
  disk; `validateEntryPath` enforces a char allowlist, rejects absolute and `..`;
  strict-mode parser rejects non-file/dir entries (blocks sym/hardlinks); per-
  entry, total, entry-count and path-length limits bound decompression bombs.
- Verdict: not a finding.

## H7 — loadOptions/resourceLocator uses any credential id (credential-use escalation) — REFUTED
- Rule (I2/I3): design-time node method calls may use only credentials the caller
  can access.
- Counter-evidence: `DynamicNodeParametersService.refineResourceIds` throws
  `ForbiddenError` when any payload credential id lacks `credential:read` for the
  user, and requires `credential:connect` for end-user (resolvable) credentials;
  inaccessible projectId/workflowId are scrubbed.
- Verdict: not a finding.

## H8 — Public API bypasses internal RBAC (divergent authz) — REFUTED
- Counter-evidence: public API `projectScope`/`globalScope` middleware call the
  same `userHasScopes`; an additional api-key-scope layer narrows, never widens.
  `publicApiCompositeScope` defers to the handler, and both current handlers
  (`n8n-packages` export/import) enforce api-key scopes explicitly AND the
  service enforces per-entity resource access (H4/H5).
- Verdict: not a finding.

## H9 — List-query `filter`/`select` enables column injection or over-broad reads — REFUTED
- Counter-evidence: filters parsed through `class-transformer` with
  `excludeExtraneousValues`; only `@Expose()`-decorated, type-validated fields
  survive; unknown fields dropped.
- Verdict: not a finding (SQL-level parameterization not separately audited; low
  concern given the allowlist).

## H10 — SSRF: node HTTP requests reach internal hosts — BY-DESIGN (config), OPEN (bypass)
- Finding: `SsrfProtectionConfig.enabled = false` by default; when off,
  `OutboundHttp.resolveSsrf` returns `'disabled'` and no IP/hostname checks run.
  Documented as intentional (self-hosted internal-service compatibility).
- The engine itself is correct when enabled (connect-time secure lookup defeats
  TOCTOU; redirects re-checked; IP-literals/IPv6 handled; metadata range in
  default blocklist).
- OPEN sub-hypothesis: a nodes-base node using a direct HTTP client (not
  `OutboundHttp`) would bypass the guard even when enabled. Not yet searched
  exhaustively. See next-steps.
- Verdict: config posture = by-design (F-C1); bypass hunt = open.

## H11 — Source Control `repositoryUrl` enables git transport/argument RCE — CONFIRMED (F-1)
- Rule (I8/I9 + RBAC intent): the `sourceControl:manage` capability should not
  grant host OS command execution.
- Path: `POST /rest/source-control/preferences` → `validateSourceControlPreferences`
  (class-validator, `repositoryUrl` is `@IsString()` only) → `initRepository` →
  `git.addRemote(origin, repositoryUrl)` → `fetch()`. No `GIT_ALLOW_PROTOCOL`
  set. `ext::sh -c '<cmd>'` → git `ext` transport executes `<cmd>` on `fetch`.
- Counter-evidence sought: a URL validator or protocol restriction in
  source-control.ee — none found (grep for `GIT_ALLOW_PROTOCOL`, `new URL(`,
  `validateRemoteUrl`, `::`, `ext::` all empty for that module).
- Confirming evidence that this is a gap (not by-design): the sibling
  `promotions.ee` module validates the same input (`validateRemoteUrl` rejects
  `::`, leading `-`, non-http(s)/ssh) and the Git node sets `GIT_ALLOW_PROTOCOL`.
- Safe PoC: `audit/poc/f1-repo-url-validation-gap.mjs` shows 4 malicious URL
  forms accepted by source-control's check, rejected by promotions'.
- Trust-boundary nuance: escalation is clearest for a custom-role holder of the
  settings-"Manage" bundle (has `sourceControl:manage`, lacks
  `communityPackage:install`); owner = self-compromise (out of scope); default
  admin overlaps existing community-package RCE. See F-1.
- Verdict: CONFIRMED code-level finding; RCE not detonated (out of scope).

## Refuted hypotheses summary
H1–H9 each had a specific control found in code. The consistent pattern: n8n
threads the acting user + required scope into every resource resolver and re-
checks at each boundary (including transitive and cross-process design-time
paths). No category-(a) vulnerability confirmed in these flows.

# Coverage — flows reviewed and gaps

Commit `5933694`, n8n 2.40.0. Legend: ✅ reviewed, control verified present/correct;
◑ partially reviewed; ⬜ not reviewed (gap).

## Reviewed — control verified

| # | Flow / surface | Files | Result |
|---|---|---|---|
| C1 | RBAC scope enforcement (project/global, mask model) | `@n8n/permissions/{combine-scopes,has-scope,role-maps,get-resource-permissions}`, `cli/permissions.ee/check-access.ts`, `cli/controller.registry.ts` | Correct. Project-scope requires user project-role covering all scopes AND resource sharing-role covering scope (DB join). Global bypass by design. |
| C2 | Credential read vs use vs decrypt (getOne) | `credentials.controller.ts`, `credentials.service.ee.ts:getOneForUser`, `credentials.service.ts:decrypt/redact` | Correct. Decrypt needs `credential:update`; `decrypt()` redacts unless `includeRawData`; connect-only → redacted blueprint. |
| C3 | Credential list incl. `includeData` | `credentials.service.ts:getMany/getManyForMemberUser/addDecryptedDataToCredentials` | Correct. Data only for `credential:update`-scoped rows, still redacted; member query filtered by sharing subquery; personal-project cross-user guard. |
| C4 | Binary-data FS path handling | `@n8n/blob-storage/fs-byte-store.ts:getAbsolutePath` | Correct. Rejects `..`/absolute after resolve. |
| C5 | Binary-data HTTP access (IDOR + traversal) | `binary-data.controller.ts`, `binary-data-access.service.ts` | Correct. `hasReadAccess` gates on `workflow:read` of owning workflow/execution; `..` rejected; `/signed` needs valid signed token. |
| C6 | List-query filter injection | `middlewares/list-query/filter.ts`, `dtos/*.filter.dto.ts`, `base.filter.dto.ts` | Correct. `class-transformer` `excludeExtraneousValues` allowlist; typed fields only. |
| C7 | Public API authorization | `public-api/v1/shared/middlewares/global.middleware.ts`, `credentials.handler.ts` | Correct. Reuses `userHasScopes`; layered api-key-scope check. No divergence from internal authz. |
| C8 | Package export authorization (per entity) | `n8n-packages.service.ts:writeExport`, `workflow.exporter.ts`, `workflow-dependency-resolver.ts` | Correct. `findWorkflowsByIdsForUser(..., ['workflow:export'])` + `assertEveryRequestedEntityAccessible`; transitive resolver re-checks each hop and skips inaccessible. |
| C9 | Package export credential values | `credential.exporter.ts`, `credential-export-policy.ts` | Correct/by-design. Gated on `credential:read`; only expression-typed strings travel; raw secrets + `oauthTokenData` filtered; `no-values` never decrypts. |
| C10 | Package import tar handling | `io/tar/tar-package-reader.ts` | Correct. In-memory only (no disk write), path allowlist + `..` reject, strict mode (no symlink/hardlink), size/entry/bomb limits, manifest-first. |
| C11 | Package import credential binding | `credential-matcher.ts`, `id-based-credential-matcher.ts` | Correct. Binds only to `getCredentialsAUserCanUseInAWorkflow(user, projectId)`; type must match. No credential-use escalation. |
| C12 | SSRF protection engine | `@n8n/backend-network/ssrf/ssrf-protection.service.ts`, `http/outbound-http.ts`, `@n8n/config/ssrf-protection.config.ts` | Control correct (connect-time secure lookup defeats TOCTOU; redirect re-check; IP-literal + IPv6 handled). **Off by default** (`enabled=false`) = documented by-design (see findings F-C1). |
| C13 | Dynamic node parameters (loadOptions/resourceLocator) credential use | `dynamic-node-parameters.controller.ts`, `dynamic-node-parameters.service.ts:refineResourceIds` | Correct. Throws `ForbiddenError` for credential ids without `credential:read`; end-user creds need `credential:connect`; projectId/workflowId scrubbed if inaccessible. |
| C14 | Expression sandbox (AST) | `workflow/src/expression-sandboxing.ts`, `utils.ts:isSafeObjectProperty` | Defense-in-depth present (this/globalThis neutralized, unsafe props blocked, computed access routed through `__sanitize`, class-extension guard). Not weaponized (see next-steps). |
| C15 | Dynamic credentials unauth OAuth flow | `modules/dynamic-credentials.ee/dynamic-credentials.controller.ts` | Reviewed; identity-keyed per caller, rate-limited, resolvable-OAuth-only, documented rationale. No obvious boundary break; deep resolver model not fully traced (◑). |

## Partially reviewed ◑
- Dynamic-credentials resolver internals (token storage keying, `validateIdentity`, csrf state binding) — controller-level only.
- Unauth route inventory: enumerated (`skipAuth`/`allowUnauthenticated`), but only binary-data/signed, dynamic-credentials, and package/public-api paths traced to a decision. e2e/dev controllers assumed test-only (needs confirming they are not mounted in prod).

## Not reviewed — gaps ⬜
- Queue/scaling execution identity & data validity across main→worker (I4).
- Execution data / node-output redaction of secrets in saved runs, previews, error messages (I6, derived data).
- Webhook + Form trigger unauth execution surface (recent CVE cluster; only routing glanced). Expression double-eval in form/webhook param resolution.
- AI Agent / tools authorization & prompt-injection→tool-action boundary (I9/AI).
- Auth/session: JWT issuance, MFA enforcement edges, password-reset/invite token entropy & reuse.
- SSO (SAML/OIDC), oauth-server module, token-exchange/embed-auth.
- chat-hub, data-table module internals, source-control import/pull.
- Task runner (JS/Python) sandbox boundary and broker auth.
- Whether any nodes-base node bypasses `OutboundHttp` with a direct HTTP client (SSRF bypass when protection enabled).

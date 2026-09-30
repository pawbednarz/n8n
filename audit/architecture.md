# Architecture & trust boundaries (from code)

Commit `5933694`, n8n 2.40.0.

## Packages (relevant)

- `packages/workflow` (`n8n-workflow`): core interfaces, expression engine,
  workflow graph/traversal. Runs in both FE and BE. **Trust:** shared library;
  must treat workflow JSON as data.
- `packages/core` (`n8n-core`): execution engine, binary-data manager,
  encryption primitives, node execution context.
- `packages/cli` (`n8n`): Express server, REST controllers, auth, RBAC,
  credentials service, webhooks, scaling/queue, public API.
- `packages/nodes-base`: built-in integration nodes (HTTP Request, webhook,
  file nodes, etc.).
- `packages/@n8n/nodes-langchain`: AI/LangChain nodes (AI Agent, tools).
- `packages/@n8n/permissions`: pure RBAC scope model (roles → scopes, masks).
- `packages/@n8n/db`: persistence layer (TypeORM entities/repositories).
- `packages/@n8n/task-runner` (+ `task-runner-python`): out-of-process code
  execution for Code node (JS via `task-runner`, Python via Pyodide).

## Trust boundaries (asserted from code read)

1. **Unauthenticated → authenticated (HTTP).** `ControllerRegistry` builds a
   middleware chain per route: IP rate-limit → auth middleware
   (`AuthService.createAuthMiddleware`, unless `skipAuth`) → license → scope.
   Routes opt out of auth with `skipAuth`/`allowUnauthenticated`. Webhook /
   form / public endpoints are a separate, intentionally-unauthenticated
   surface (see webhooks).
2. **Authenticated user → resource (RBAC).** Enforced by
   `@GlobalScope`/`@ProjectScope` decorators → `createScopedMiddleware` →
   `userHasScopes` (`packages/cli/src/permissions.ee/check-access.ts`).
   - Global role scopes checked first (`allOf`); global owner/admin bypass is
     by design.
   - Otherwise: user must belong to a project whose **project role** grants ALL
     required scopes, AND the resource must be shared into that project with a
     **resource role** (`rolesWithScope`) that also grants the scope. Both
     conditions required (DB-enforced join). This is the mask model
     (`combineScopes` mask filters project/resource scopes by sharing; global
     is never masked).
3. **Right-to-use vs right-to-read a credential.** `getOne`/`getOneForUser`
   (`credentials.service.ee.ts`): decrypted data returned only to
   `credential:update` holders; `credential:read` alone → metadata only;
   `credential:connect` on a resolvable (end-user OAuth) credential → decrypted
   BUT `decrypt()` redacts secrets by default (`includeRawData=false`, see
   `credentials.service.ts:956`). **Verified-correct** in this read.
4. **Editor/API definition → execution engine.** Workflow definitions
   (expressions, node params) are authored by users with workflow write scope,
   then executed by `core`. Expression evaluation and Code node are the
   historically-sensitive boundary (many prior CVEs). Code node runs in the
   task runner (separate process).
5. **Cross-package data boundary.** `n8n-workflow` and `core` must treat
   workflow JSON and incoming item data as untrusted data, not code.
6. **Persistence boundary.** TypeORM confined to `@n8n/db` / module
   `database/` folders; business logic must not import `@n8n/typeorm`
   (lint-enforced).

## Areas mapped but not yet deep-reviewed (see coverage.md)

Auth token/session, webhooks (unauth surface), binary-data path handling,
import/export, execution identity in queue mode, SSRF controls in HTTP/MCP
nodes, AI Agent tool authorization, derived-data redaction (logs/telemetry).

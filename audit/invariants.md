# Security invariants (expected properties) + basis

Each invariant: the rule, its basis in code/tests/docs, and how a violation
would look. "Basis" = where the code asserts/relies on it.

## I1 — RBAC: right user → right resource
A user may act on a workflow/credential/project/data-table only via a role that
grants the required scope, in a project the resource is shared into.
- Basis: `check-access.ts:userHasScopes` (project-scope join requires the user's
  project role to cover ALL scopes AND the resource sharing role to cover the
  scope); `@ProjectScope`/`@GlobalScope` decorators + `createScopedMiddleware`
  (`controller.registry.ts`). Mask model in `@n8n/permissions/combine-scopes`.
- Violation: acting on a resource in a project the user is not a qualifying
  member of; or a route missing the scope decorator; or a param name mismatch
  so `userHasScopes` falls through.

## I2 — Credential use vs read separation
Holding "use/connect" on a credential must not reveal its secret values;
decrypted secrets go only to users who can edit (proxy for decrypt), and even
then the API returns redacted secrets.
- Basis: `credentials.service.ee.ts:getOneForUser` (decrypt only with
  `credential:update`; connect-only → redacted); `credentials.service.ts:decrypt`
  redacts unless `includeRawData`.
- Violation: a path returning raw secret values to a read/connect/use-only user,
  or leaking them via export, logs, error messages, or execution data.

## I3 — Unambiguous acting identity
Every operation resolves a single, correct acting identity; execution uses the
workflow's/credential owner's authority, not an escalated one.
- Basis: auth middleware sets `req.user`; execution passes an identifier
  (`executing-user-identifier*`). To be traced in execution/queue path.
- Violation: an operation that runs with more authority than the requester, or
  attributes an action to the wrong user.

## I4 — Security context preserved across components/processes
When work crosses process boundaries (main → worker/queue, main → task runner),
the permission/identity context and data constraints are preserved.
- Basis: scaling/queue (`packages/cli/src/scaling`), task-runner packages.
- Violation: a worker executing with different (broader) authority, or a task
  runner reachable with a workflow that should not run there.

## I5 — Post-permission-change / ownership-change consistency
After unshare / transfer / role change, previously-granted access stops; caches
and derived grants are invalidated.
- Basis: `transferOne` drops all sharings + cleans orphaned connections;
  cache invalidation to be traced.
- Violation: stale access after unshare/transfer; cached decrypted data usable
  after access removed.

## I6 — Derived data protection (logs, results, telemetry, errors)
Secrets are redacted from execution results, logs, error messages, telemetry;
access to execution results follows workflow:read.
- Basis: binary-data access gated on `workflow:read`
  (`binary-data-access.service.ts`); credential redaction (I2); telemetry
  catalog. Redaction in execution data to be traced.
- Violation: secrets or another tenant's data surfacing in an execution result,
  log line, error, preview, or telemetry event.

## I7 — File path confinement (import/export, binary, node file ops)
File reads/writes derived from user input stay within their intended root; no
`..`/absolute traversal; no arbitrary file read/write across the trust boundary.
- Basis: `FsByteStore.getAbsolutePath` (rejects `..`/absolute);
  `binary-data.controller.validateBinaryDataId` (rejects `..`). Import/export &
  node file ops to be traced.
- Violation: reading/writing outside the root via crafted id/path/name.

## I8 — SSRF confinement
Server-side HTTP from nodes (HTTP Request, webhook fetches, MCP client) must not
be usable to reach internal-only resources beyond product intent.
- Basis: to be located (axios layer / block lists). n8n historically ships an
  optional SSRF/host filter.
- Violation: a documented control that can be bypassed to reach internal hosts.

## I9 — Expression / code execution confinement
Expression evaluation and Code node execute with only their intended
capabilities; no escalation beyond the acting user's already-granted ability to
run code, and no reach into the host beyond the sandbox contract.
- Basis: expression engine (`n8n-workflow`), task runner sandbox. NOTE:
  authenticated code execution *at the actor's own level* is by-design (see
  scope.md A1); only escapes crossing a boundary qualify.
- Violation: sandbox escape granting host access beyond contract, or expression
  eval reachable by a lower-privileged actor (e.g. via an unauth webhook/form).

## I10 — Unauthenticated surface minimality
`skipAuth`/`allowUnauthenticated` routes, webhooks, and forms expose only their
intended function and enforce their own token/ownership checks.
- Basis: `controller.registry.ts` (skipAuth), `binary-data/signed`
  (signed token), webhook routing. To be traced.
- Violation: an unauth route reaching authenticated functionality or another
  tenant's data.

# Bug-bounty report drafts

## Report 1 — Authenticated RCE via unvalidated Source Control repository URL (git `ext::` transport)

> Verified at code level (full call path read) + safe validation-gap PoC. The
> RCE itself was **not** detonated (weaponization is out of engagement scope).
> Confirm program scope and dedup (advisory access was blocked here) before
> submitting.

**Summary.** n8n's Source Control (Environments) feature persists a
user-supplied `repositoryUrl` with no format or protocol validation and hands it
directly to `git` (`git remote add` + `git fetch`) via `simple-git`. A value
using git's `ext::` transport (e.g. `ext::sh -c '<command>'`) causes `git fetch`
to execute `<command>` on the n8n host. Any principal with the
`sourceControl:manage` scope can therefore run arbitrary OS commands on the
server. n8n already blocks this exact class in its sibling `promotions.ee` module
and in the Git node (`GIT_ALLOW_PROTOCOL`), but the Source Control module does
not, so this is an unintended gap.

**Affected component / version.** `packages/cli` Source Control module
(`src/modules/source-control.ee`), n8n 2.40.0 at commit `5933694` (present as
long as the source-control git init/fetch path lacks URL validation). Enterprise
feature (Source Control + custom RBAC are licensed). Applies to self-hosted; n8n
Cloud impact depends on container isolation (unverified here).

**Preconditions / privileges.**
- An authenticated account holding the `sourceControl:manage` global scope. This
  is held by owner and admin, and is assignable to a non-owner/non-admin via a
  **custom role** carrying the settings-"Manage" bundle
  (`GLOBAL_CUSTOM_ROLE_SCOPE_GROUPS.settings.Manage`), which includes
  `sourceControl:manage` but **not** `communityPackage:install`.
- Source Control must be licensed/enabled.
- The instance must not already be connected (the endpoint requires disconnect
  first for some changes; initial connect is the trigger).

**Reproduction (on a local, disposable instance — do NOT run against shared or
third-party hosts).**
1. Sign in as a user with `sourceControl:manage` (owner, or a custom
   settings-Manage role).
2. `POST /rest/source-control/preferences` with a body whose `repositoryUrl` uses
   the `ext::` transport, `connectionType: "ssh"`, `branchName: "main"`,
   `initRepo: true`. (Use a benign marker command that only writes a local file
   in your lab, never an exfiltration or destructive payload.)
3. The server runs `git remote add origin <repositoryUrl>` then `git fetch`,
   which invokes the `ext` transport and executes the command as the n8n process
   user.

**Observed vs expected.**
- Observed: the URL passes validation (`repositoryUrl` is `@IsString()` only) and
  reaches `git.addRemote` + `fetch`; git's `ext` transport executes the command.
- Expected: the URL is rejected unless it is a normal `http(s)` or `ssh` remote
  (the behaviour of `promotions.ee validateRemoteUrl` and the Git node's
  `GIT_ALLOW_PROTOCOL`).

**Impact.** Arbitrary OS command execution on the n8n host as the n8n process
user → full instance compromise: decrypt the encryption key and all stored
credentials, read every project's/tenant's data, pivot into the internal
network. For a non-owner custom-role holder this is a privilege escalation from
"manage instance settings" to host RCE.

**Suggested CVSS (v3.1).** `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` → **9.1 (Critical)**.
Rationale: network-reachable authenticated endpoint (PR:H — a privileged app
scope), no user interaction, host RCE escaping the app sandbox (S:C) with full
CIA loss. If the program scores owner/admin-only RCE lower (because default
admins already have community-package RCE), the honest rating for the *default
admin* case is closer to Medium/High; the **custom-role escalation** case
warrants the Critical rating above. Provide both framings to the triager.

**Proposed fix.** Validate `repositoryUrl` before persisting/using it: reject
control characters, a leading `-`, and `::`; require `http:`/`https:` or an
`ssh://`/scp-like remote with a host and path; reject inline credentials. Reuse
`promotions.ee`'s `validateRemoteUrl` (extract to a shared helper so Source
Control, Promotions and the Git node converge), and/or set `GIT_ALLOW_PROTOCOL`
on the source-control git env as the Git node does.

**Verified vs hypothesis.** Verified: the full call path, the absence of
validation/protocol-restriction, and the differential vs `promotions.ee`
(safe PoC, `audit/poc/f1-repo-url-validation-gap.mjs`). Hypothesis (not
detonated): that git's default `protocol.ext.allow=user` policy permits the
`ext` transport for this top-level `fetch` (no `GIT_PROTOCOL_FROM_USER=0` is
set), yielding execution. This is the standard git `ext::` RCE behaviour but was
not run here.

---

## Secondary candidates (not submission-ready)

Below are two lower-severity candidates and exactly why each is **not**
submittable as-is.

---

### Candidate 1 — SSRF protection off by default (self-hosted)
- Component/version: `@n8n/config` SSRF config, `@n8n/backend-network`
  `OutboundHttp`; n8n 2.40.0, self-hosted.
- Summary: `N8N_SSRF_PROTECTION_ENABLED=false` by default, so guarded outbound
  requests (HTTP Request node, URL import, OAuth/discovery) can reach internal /
  loopback / cloud-metadata IPs.
- Why NOT submittable: documented by-design (see `findings.md` F-C1). It is a
  configuration posture, not a boundary bypass. An authenticated workflow author
  can already make arbitrary outbound HTTP as intended functionality. Requires
  scope confirmation (A1/A3): on n8n Cloud the flag is presumably enabled, which
  removes the issue; on self-hosted it is the operator's documented choice.
- What WOULD be submittable: a concrete bypass of the guard **while enabled**
  (e.g. a redirect/rebinding path the connect-time lookup misses, or a node that
  skips `OutboundHttp`). F-B1 investigated the "skips OutboundHttp" angle for the
  built-in node packages and largely refuted it.
- CVSS: not scored (not a confirmed vulnerability).

---

### Candidate 2 — Credential expression values exported to `credential:read` holders
- Component/version: `n8n-packages` module, public-API package export; n8n 2.40.0.
- Summary: package export decrypts a credential fetched with only
  `credential:read` and includes its expression-typed field values in the
  archive; the normal API reserves decrypt for `credential:update` and redacts.
- Why NOT submittable: no secret crosses the boundary — `filterValue`
  (`credential-export-policy.ts`) keeps only strings containing `{{…}}`
  expressions and drops literal secrets and `oauthTokenData`. The disclosed data
  is references/templates (e.g. `={{$env.X}}`), i.e. credential *structure*, not
  the secret. Impact does not rise to a credential-disclosure vulnerability.
  Also requires `workflow:export` on a workflow referencing the credential.
- What WOULD raise it to (a): a case where `filterValue` lets a literal secret
  through (e.g. a secret that itself contains `{{`/`}}`, or a field type whose
  raw value is expression-shaped). Worth a targeted property test (see
  `findings.md` F-B2 suggested test) — currently a hardening item.
- CVSS: not scored.

---

## Deduplication note (Stage 6)
Public advisory sources (GitHub Security Advisories, NVD, OSV, n8n.io, the VDP
page) are **blocked by this environment's network egress policy**; I could not
consult them. I therefore make **no** novelty or duplicate claim. Since no
category-(a) finding was confirmed, dedup is moot for now. If a finding is
confirmed later, dedup by root cause + trust boundary against those sources is a
required pre-submission step (`next-steps.md` N5).

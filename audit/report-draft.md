# Bug-bounty report drafts

## Status: no submission-ready report

No category-(a) vulnerability was confirmed in the reviewed surfaces
(commit `5933694`, n8n 2.40.0). Per the engagement rules, only a confirmed,
trust-boundary-violating finding with real impact is drafted here. There is
none. A report with zero confirmed vulnerabilities is a valid outcome when
coverage, evidence and limitations are documented — see `coverage.md`,
`hypotheses.md`, `findings.md`.

Below are the two closest candidates and exactly why each is **not** submittable
as-is, so a follow-up session (or the program triager) can decide.

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

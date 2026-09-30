#!/usr/bin/env node
/*
 * SAFE PoC for finding F-1 — Source Control `repositoryUrl` validation gap.
 *
 * This does NOT execute git, does NOT run any command, and contains no
 * exploit payload. It only demonstrates the *validation differential*:
 *   - the value n8n hands to `git addRemote`/`fetch` in source-control.ee
 *     passes source-control's validation, while
 *   - the SAME value is rejected by the sibling promotions.ee validator that
 *     exists specifically to stop this class.
 *
 * Dependencies are NOT installed in this container (node_modules is empty), so
 * the real modules cannot be imported and executed here — this is an
 * environment limitation. The logic below is copied VERBATIM from the cited
 * source so the comparison is faithful:
 *
 *   source-control accept side  = the effective check in
 *     packages/cli/src/modules/source-control.ee/types/source-control-preferences.ts:13-14
 *       @IsString() repositoryUrl: string;   // no format/protocol constraint
 *     (validateSourceControlPreferences runs only class-validator, so a string
 *      value satisfies it — nothing else is checked.)
 *
 *   reject side = packages/cli/src/modules/promotions.ee/promotions-git.service.ts:88-131
 *     validateHttpRemoteUrl / validateSshRemoteUrl (copied verbatim below).
 */

// ---- source-control.ee effective validation (from the @IsString() decorator) ----
function sourceControlAccepts(repositoryUrl) {
	// class-validator @IsString() with no other decorator: passes iff it's a string.
	return typeof repositoryUrl === 'string';
}

// ---- promotions.ee validation, copied verbatim from promotions-git.service.ts ----
class BadRequestError extends Error {}

function validateRemoteUrl(remoteUrl, authType) {
	for (const char of remoteUrl) {
		const code = char.charCodeAt(0);
		if (code < 32 || code === 127) {
			throw new BadRequestError('Remote URL must not contain control characters');
		}
	}
	if (authType === 'token') validateHttpRemoteUrl(remoteUrl);
	else validateSshRemoteUrl(remoteUrl);
}

function validateHttpRemoteUrl(remoteUrl) {
	let url;
	try {
		url = new URL(remoteUrl);
	} catch {
		throw new BadRequestError('Remote URL must be a valid HTTP or HTTPS URL');
	}
	if (!['http:', 'https:'].includes(url.protocol)) {
		throw new BadRequestError('Username and password providers require an HTTP(S) remote URL');
	}
	if (url.username || url.password) {
		throw new BadRequestError('Remote URL must not contain credentials');
	}
}

function validateSshRemoteUrl(remoteUrl) {
	const error = new BadRequestError('SSH key providers require an ssh:// or [user@]host:path remote URL');
	if (remoteUrl.startsWith('-') || remoteUrl.includes('::')) throw error;
	const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(remoteUrl);
	if (scheme) {
		if (scheme[1].toLowerCase() !== 'ssh') throw error;
		let url;
		try {
			url = new URL(remoteUrl);
		} catch {
			throw error;
		}
		if (url.password) throw new BadRequestError('Remote URL must not contain credentials');
		if (!url.hostname || !url.pathname || url.pathname === '/') throw error;
		return;
	}
	if (process.platform === 'win32' && /^[a-zA-Z]:/.test(remoteUrl)) throw error;
	const isScpLike = /^(?:[a-zA-Z0-9_.-]+@)?[a-zA-Z0-9._][a-zA-Z0-9._-]*:[^\s]+$/.test(remoteUrl);
	if (!isScpLike) throw error;
}

function promotionsRejects(repositoryUrl) {
	// Try both auth modes; "rejected" means neither mode accepts it.
	for (const authType of ['token', 'key']) {
		try {
			validateRemoteUrl(repositoryUrl, authType);
			return false; // one mode accepted it
		} catch {
			/* rejected in this mode */
		}
	}
	return true;
}

const cases = [
	{ url: 'ext::sh -c AAAA', note: 'git ext transport = command execution vector' },
	{ url: 'fd::17/foo', note: 'git fd transport' },
	{ url: '-oProxyCommand=xxx', note: 'leading-dash argument injection' },
	{ url: 'file:///etc/passwd', note: 'local file transport' },
	{ url: 'https://github.com/acme/repo.git', note: 'legitimate https remote' },
	{ url: 'git@github.com:acme/repo.git', note: 'legitimate scp-like ssh remote' },
];

let gapCount = 0;
console.log('url'.padEnd(40), 'source-control', 'promotions', 'note');
console.log('-'.repeat(100));
for (const { url, note } of cases) {
	const scAccept = sourceControlAccepts(url);
	const promoReject = promotionsRejects(url);
	const isGap = scAccept && promoReject; // source-control accepts what promotions blocks
	if (isGap) gapCount++;
	console.log(
		url.padEnd(40),
		(scAccept ? 'ACCEPT' : 'reject').padEnd(14),
		(promoReject ? 'REJECT' : 'accept').padEnd(10),
		note + (isGap ? '   <== GAP' : ''),
	);
}
console.log('-'.repeat(100));
console.log(
	`\n${gapCount} malicious URL form(s) are ACCEPTED by source-control.ee but REJECTED by promotions.ee.`,
);
console.log(
	'These are the values source-control.ee hands to `git addRemote` + `fetch` unvalidated.',
);
process.exit(0);

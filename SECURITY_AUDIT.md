# Security Audit — tier2tickets-relay

**Scope:** Full adversarial review of the Cloudflare Worker that impersonates a
HaloPSA/ITSM instance so Tier2Tickets / Helpdesk Buttons can create tickets in
Gorelo PSA. The Worker holds a live Gorelo write key and an `ADMIN_KEY`, and
moves customer PII/PHI (names, emails, phones, device details) through a D1
mirror.

**Reviewed at commit:** `fa50701` (branch `main`), all of `src/`, `migrations/`,
`scripts/`, `wrangler.toml`, `.dev.vars.example`, `.gitignore`, `package.json`,
`package-lock.json`, `renovate.json`, `tsconfig.json`, `vitest.config.ts`,
`test/`, `docs/`, full git history (83 commits, all branches). No `.github/`
workflows exist.

---

## 1. Executive summary

The relay's authentication is **IP-allowlist-only**. The `POST /token` OAuth
endpoint mints a bearer token, but **no resource or create endpoint ever
validates a token** — `/users`, `/client`, `/site`, `/asset`, `/tickets`,
`/actions` are served purely on the strength of the `CF-Connecting-IP` check
(`src/halo.ts:1112`). The advertised `HALO_CLIENT_ID`/`HALO_CLIENT_SECRET`
control (README "Security") is therefore **auth theater**: a caller who never
calls `/token`, or who fails the credential check there, can still hit every
data endpoint directly. The one real control, `ENFORCE_IP_ALLOWLIST`, is
**fail-open** — anything other than the exact string `"true"` (unset, empty,
`"false"`, `"True"`) disables it (`src/tier2.ts:8`). The shipped `wrangler.toml`
does set it to `"true"`, and Cloudflare overwrites `CF-Connecting-IP` so it
cannot be spoofed, so the reference deployment is not currently open to the
internet — but the entire security posture of a system holding a live PSA write
key and PHI rests on one mutable plaintext var with no defense in depth. That is
the finding that matters. **(F1 / F2)**

Second-order: with `DEBUG_LOGS` off the Worker is *nearly* silent, but two
ungated `console.error` paths defeat the "no PII/PHI, no payload when debug is
off" acceptance test — the raw Gorelo error-response body
(`src/halo.ts:952`) and the generic handler-error string that is also echoed to
the caller in the 500 body (`src/halo.ts:1129-1130`) — and the always-on
`HALO routing:` line logs the device hostname (`src/halo.ts:543`). Platform-level
`invocation_logs` (`wrangler.toml:10`) capture request metadata regardless of
source silence. **(F3 / F4)**

On the axes that are frequently weak, this codebase is genuinely solid: **HTML
injection into the Gorelo ticket body is correctly mitigated** (everything is
run through `esc()`), **SQL is fully parameterized** (no user string is ever
concatenated into a query), **no secrets are committed** (history is clean, only
config ids live in `wrangler.toml`), the **Gorelo key is never logged**, and the
**supply chain is minimal and pinned** (one runtime dep, no transitive deps, all
registry-resolved with integrity hashes). Those axes get one line each below and
no manufactured findings.

---

## 2. Findings table

| ID | Title | Severity | Location | Impact |
|----|-------|----------|----------|--------|
| F1 | OAuth bearer token is never validated on any endpoint | **Critical** | `src/halo.ts:1104-1145`, `handleApi` | The `/token` flow and `HALO_CLIENT_ID/SECRET` provide zero protection; every data/create endpoint is reachable without any token |
| F2 | IP allowlist is the sole control and is fail-open | **High** | `src/tier2.ts:7-11` | If `ENFORCE_IP_ALLOWLIST` is unset/`"false"`, the whole Halo mock (PII reads + unauth Gorelo ticket writes + syncAll amplification) is open to the internet |
| F3 | Ungated error logging leaks Gorelo response body + internals with `DEBUG_LOGS` off; 500 echoes internals to caller | **Medium** | `src/halo.ts:952`, `:1129-1130` | Fails the log-silence acceptance test; potential PII/PHI in logs; internal error disclosure in HTTP response |
| F4 | No single logging chokepoint; `HALO routing:` logs hostname unconditionally; platform `invocation_logs` on | **Medium** | `src/halo.ts:543`, `wrangler.toml:8-10` | Borderline PII (hostnames often embed usernames) with debug off; every `console.*` hand-branches, so silence is easy to regress |
| F5 | Full caller control of ticket routing / contact binding | **Medium** | `src/halo.ts:483-531`, `422-428` | A malicious or compromised Tier2 press can attribute a ticket to any Gorelo client/contact and trigger a "ticket created" email to any matched contact |
| F6 | `ADMIN_KEY` comparison is not constant-time | **Low** | `src/index.ts:101` | Timing side channel on the admin key (theoretical over the network) |
| F7 | No rate limiting; deferred-queue & syncAll amplification | **Low** | `src/halo.ts:840-866`, `src/sync.ts` | A caller past the IP gate can flood `pending_tickets` / force unbounded Gorelo writes |
| F8 | Dead-letter notify-failure log may include a `NOTIFLY_URLS` secret | **Low / unverified** | `src/halo.ts:997-1001` | If notifly's per-destination error string echoes the URL, a Teams `sig=` token could land in logs |

Passing axes (no finding): HTML/XSS sink, SQL injection, committed secrets,
Gorelo-key logging, dependency/supply-chain, CI (none present).

---

## 3. Detailed findings

### F1 — OAuth bearer token is never validated (Critical)

**Description.** `POST /token` (`handleToken`, `src/halo.ts:167-188`) mints
`access_token = crypto.randomUUID()...` and returns it. It optionally validates
`HALO_CLIENT_ID`/`HALO_CLIENT_SECRET` *at issuance*. But the token is never
stored and **never checked** on any subsequent request. `handleHalo`
(`:1104-1145`) applies exactly one gate — `ipAllowed()` — then dispatches to
`handleApi`, which routes `/users`, `/client`, `/site`, `/asset`, `/tickets`,
`/actions` with no reference to `Authorization`. The only occurrences of
`Bearer`/`access_token` in `src/halo.ts` are the *issuance* response
(`:183-184`); grep confirms no inbound bearer check exists.

**Exploitation path.** Any request that passes the IP check can skip `/token`
entirely and directly `POST /tickets` + `POST /actions` to create Gorelo
tickets, or `GET /users?search=<email>` / `GET /client` / `GET /asset` to
enumerate contacts, clients and devices (names, emails, serials, IPs) out of the
D1 mirror. Setting `HALO_CLIENT_ID`/`HALO_CLIENT_SECRET` — the documented way to
"lock down" the mock — changes nothing on these endpoints; it only makes
`/token` return 401, which no attacker needs to call. This is why the README
"OAuth2 client_credentials + IP allowlist" row overstates the control.

**Evidence.**
```ts
// src/halo.ts — handleHalo: the ONLY gate is the IP check
if (!ipAllowed(request, env)) {                       // :1112
  console.warn("HALO rejected: source IP not allowlisted");
  return jsonResponse(403, { error: "forbidden" });
}
// ...no token check anywhere below...
res = await handleApi(request, env, ctx, url, body);  // :1126  serves /users, /tickets, ...
```

**Fix.** Make the minted token real and require it on every non-`/token` Halo
resource. Minimal version — a signed, self-verifying token (no storage needed):

```ts
// issue: sign instead of random
const token = await signToken(env, { exp: Date.now() + 3600_000 });
// enforce in handleHalo, after ipAllowed and before ensureSynced/handleApi:
if (haloResource(url.pathname) !== "token") {
  const auth = request.headers.get("Authorization") ?? "";
  const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  if (!(await verifyToken(env, bearer))) {
    return jsonResponse(401, { error: "invalid_token" });
  }
}
```
where `signToken`/`verifyToken` use HMAC-SHA256 over the payload with a new
`HALO_TOKEN_SECRET`. This turns the OAuth flow into a genuine second factor
alongside the IP allowlist. (If Tier2's Halo client cannot be relied on to send
the token back, at minimum require `HALO_CLIENT_ID/SECRET` to be set and treat
the IP allowlist as mandatory — see F2 — rather than presenting OAuth as a
control it isn't.)

---

### F2 — IP allowlist is the sole control and is fail-open (High)

**Description.** With F1, `ipAllowed()` is the *entire* authentication of the
Halo mock. It is fail-open:

```ts
// src/tier2.ts
export function ipAllowed(request: Request, env: Env): boolean {
  if (env.ENFORCE_IP_ALLOWLIST !== "true") return true;   // :8  ANY non-"true" => allow all
  const ip = request.headers.get("CF-Connecting-IP") ?? "";
  return TIER2_SOURCE_IPS.has(ip);                          // :10 exact match, fail-closed at this level
}
```

Unset, empty, `"false"`, or even `"True"`/`"TRUE"` (case mismatch) all disable
enforcement and serve every caller. The header check itself is sound:
`CF-Connecting-IP` is set by Cloudflare's edge and a client-supplied value is
overwritten, so IPs cannot be spoofed to Tier2's two addresses, and an absent
header fails closed (`"" ∉ set`). The shipped `wrangler.toml:24` sets
`ENFORCE_IP_ALLOWLIST = "true"`, so the reference deployment enforces. The risk
is the fail-open **default** on a plaintext var with no defense in depth: a
deploy that drops the var, a copy-paste that sets `"false"` during debugging (cf.
the `DEBUG_LOGS` on/off commits in history), or a case typo silently exposes a
live-Gorelo-write-key, PHI-bearing endpoint to the internet.

**Exploitation path.** If the toggle is ever off: unauthenticated internet
callers get everything in F1 — contact/asset/client enumeration and arbitrary
Gorelo ticket creation on the MSP's tenant, plus `syncAll()` amplification (F7).

**Fix.** Fail closed and normalize:
```ts
export function ipAllowed(request: Request, env: Env): boolean {
  const flag = (env.ENFORCE_IP_ALLOWLIST ?? "true").trim().toLowerCase();
  const enforce = flag !== "false" && flag !== "0" && flag !== "";  // default ON
  if (!enforce) return true;
  return TIER2_SOURCE_IPS.has(request.headers.get("CF-Connecting-IP") ?? "");
}
```
Default to enforcing; require an explicit `"false"` to disable. Consider also
gating on `HALO_CLIENT_ID/SECRET` presence so the mock refuses to serve if
neither the IP allowlist nor OAuth is active.

---

### F3 — Ungated error logging leaks response body & internals; 500 echoes internals (Medium)

**Description.** The log-silence acceptance test requires that with `DEBUG_LOGS`
off, no emitted line carries PII/PHI, a secret, or a raw request/response body.
Two always-on error paths violate it:

```ts
// src/halo.ts:952 — logs the raw Gorelo error-response body, ungated
console.error(`HALO action gorelo create rejected status=${err.status} response=${err.body}`);
```
`err.body` is Gorelo's response text on a failed `POST /v1/tickets`. Validation
errors from such APIs commonly echo the offending field values — here the ticket
`title`, `createdByName`, and the full HTML `description` built from the report
(names, emails, phones, device detail). This fires on every create rejection,
regardless of `DEBUG_LOGS`.

```ts
// src/halo.ts:1129-1130 — generic handler error, ungated + returned to caller
console.error(`HALO handler error ${request.method} ${url.pathname}:`, String(err));
res = jsonResponse(500, { error: "internal_error", detail: String(err).slice(0, 300) });
```
`String(err)` for an unexpected exception can contain a value from the request
(e.g. a `TypeError`/parse message quoting body content), and `detail` returns up
to 300 chars of it to the caller — internal-detail disclosure in the HTTP
response, not just the log.

Lower-grade siblings on the same pattern: `:944`, `:1048`, `:1057`, `:1100`,
`src/index.ts:28/76/86` log `String(err)`/`describeError(err)`. `describeError`
is well-designed (GoreloError → `status=` only; otherwise `name: message`) and
`String(GoreloError)` omits the body, so these are low-risk, but they are still
ungated `message` sinks.

**Fix.** Never log `err.body`; never return `String(err)` to the caller. Reduce
to a scrubbed breadcrumb:
```ts
// :952
console.error(`HALO action gorelo create rejected halo_id=${haloId} status=${err.status}`);
// gate the raw body behind debug only:
if (debugOn(env)) console.error(`  gorelo body: ${err.body.slice(0, 500)}`);

// :1129-1130
const reqId = crypto.randomUUID().slice(0, 8);
console.error(`HALO handler error ${request.method} ${url.pathname} id=${reqId} ${describeError(err)}`);
res = jsonResponse(500, { error: "internal_error", request_id: reqId });
```

---

### F4 — No logging chokepoint; hostname logged unconditionally; platform invocation logs (Medium)

**Description.** There is no single `log()`/`debug()` helper — every call site
hand-branches on `debugOn(env)` or emits raw `console.*`. The audit standard
treats the absence of one chokepoint as a finding, because silence is one careful
edit away from regressing (and already has gaps — F3). Concretely, the
always-on routing line logs the device hostname:

```ts
// src/halo.ts:543-548 — emitted with DEBUG_LOGS OFF
console.log(
  `HALO routing: emailMatch=${email ? "y" : "n"} hostname=${hostname || "(none)"} ...`
);
```
The code deliberately withholds the email here (`email` is only logged under
`debugOn`, `:549`) but prints `hostname` unconditionally. Hostnames routinely
embed a person's name (`ELI-BRODY-PC`, `jsmith-laptop`), so this is borderline
PII with debug off — the same category the surrounding code is trying to protect.

Platform layer: `wrangler.toml:8-10` enables `[observability.logs]` with
`invocation_logs = true`; the comment itself notes it captures "the raw Gorelo
create response and any upstream failure bodies." Even with perfect source-level
silence, invocation logs record every request's metadata into the dashboard
(subject to Cloudflare retention). If the standard is genuinely "none," this
config is part of the verdict.

**Fix.** (a) Introduce one chokepoint and route all non-error breadcrumbs through
it: `const debug = (env, msg) => { if (debugOn(env)) console.log(msg); }` and a
separate always-on `breadcrumb()` that only accepts a fixed set of non-PII
fields. (b) Drop `hostname` from `:543` (log `host=${hostname ? "y" : "n"}`), or
gate it. (c) Decide deliberately on `invocation_logs`: set `head_sampling_rate`
low or disable if "no PII in logs" is a hard requirement, and document the choice.

---

### F5 — Full caller control of routing / contact binding (Medium — trust-boundary / defense-in-depth)

**Description.** Ticket routing trusts request-supplied identifiers. `user_id`
is looked up directly (`getContactById(uid)`, `:493`); `client_id`,
`site_id`, and `assets[].client_id/site_id` are used as routing signals
(`:514-528`); and any of six requester-email fields (`:422-428`) or a parsed
report email selects the contact. A caller past the IP gate — i.e. a compromised
or malicious Tier2 press — can therefore attribute a Gorelo ticket to an
arbitrary client/contact of the MSP's tenant, set `createdByName` to a victim,
and (with `SEND_TICKET_CREATED_EMAIL=true`, `wrangler.toml:71`) cause Gorelo to
email any contact the press resolves to (`:829`). There is no per-tenant
authorization because the design intentionally trusts Tier2.

**Assessment.** This is inherent to impersonating a single-tenant PSA for a
trusted integrator; it is **defense-in-depth**, not a standalone break, and its
exploitability is entirely downstream of F1/F2 (you must be past the only gate).
Worth recording because it raises the blast radius of an F1/F2 failure from
"create noise tickets" to "spoof tickets/emails as arbitrary customers."

**Fix.** Primarily, close F1/F2. Secondarily, constrain the email trigger to the
report-derived contact only (already the case) and consider ignoring a
request-supplied `user_id` that resolves to a contact whose `client_id` conflicts
with the report-derived client.

---

### F6 — `ADMIN_KEY` comparison is not constant-time (Low)

**Description.** `adminKeyOk` compares with `===`:
```ts
// src/index.ts:95-102
if (!env.ADMIN_KEY) return false;                       // empty-env guarded — good
const provided = request.headers.get("X-Admin-Key") ?? request.headers.get("X-API-Key") ?? bearer;
return provided === env.ADMIN_KEY;                       // :101 not constant-time
```
The three parsing paths are equally strict and the empty-key case is guarded
(missing headers yield `""`/absent, which never equals a non-empty key), so
there is no bypass. The only issue is the non-constant-time compare — a timing
side channel. Over the network, through Cloudflare's variable latency, this is
close to unexploitable; it is a hardening item.

**Fix.** Constant-time compare:
```ts
function timingSafeEq(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a), eb = new TextEncoder().encode(b);
  if (ea.length !== eb.length) return false;
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i]! ^ eb[i]!;
  return diff === 0;
}
```

---

### F7 — No rate limiting; deferred-queue & syncAll amplification (Low)

**Description.** No route is rate-limited. A caller past the IP gate can:
(a) loop `POST /tickets` to grow `pending_tickets` unbounded and, via `/actions`
or the `*/5` cron, force unbounded `POST /v1/tickets` to Gorelo (cost /
rate-limit exhaustion); (b) trigger `syncAll()` amplification — every first-call
bootstrap (`ensureSynced`, `:1096-1102`) and every `/admin/sync` fans out
`listAgents` + `listClients` + per-client `listLocations`/`listContacts`. Each
press also makes a live `getAgent` call (`:536`). Gated by the IP allowlist
today, so realistic abuse requires F1/F2 to be open, or a compromised Tier2.
`takeStalePendingTickets` caps each flush at `LIMIT 50` (`src/db.ts:314`), which
bounds per-cron work but not total queue growth. Minor correctness note: a
`haloId` collision in `putPendingTicket` (`ON CONFLICT DO UPDATE`) would silently
overwrite an earlier queued ticket — negligible probability at a 2^48 surrogate
space, but it is a silent-loss path.

**Fix.** Add a coarse per-source rate limit (Cloudflare Rate Limiting rules or a
D1/KV counter) on `/tickets` and `/admin/sync`; cap `pending_tickets` row count
and shed/alert beyond a threshold.

---

### F8 — Dead-letter notify-failure log may include a `NOTIFLY_URLS` secret (Low / unverified)

**Description.** On a notifly delivery failure the per-destination error is
logged:
```ts
// src/halo.ts:997-1001
console.error(
  `HALO dead-letter notify failures halo_id=${info.haloId}: ` +
    failed.map((f) => `${f.service}:${f.error ?? "?"}`).join("; "),
);
```
`NOTIFLY_URLS` is operator-set and correctly never influenced by request input
(confirmed: `notiflyUrls(env)` is the only source for both `postDeadLetter` and
`testNotifly`), so there is **no SSRF** — priority focus area #4 passes. The
residual risk is that `f.error` from `@ambersecurityinc/notifly` might embed the
destination URL, which for a Teams Workflows target carries a secret `sig=`
token. Whether it does depends on the library's error formatting, which I could
not verify (package not installed in this environment). Flagged as a
could-not-verify hardening item.

**Fix.** Log only `f.service` and a static code, never `f.error` verbatim; or
scrub `sig=`/query strings before logging.

---

## 4. Verification of README "Security" claims

| Claim (README §Security) | Verdict | Reference |
|---|---|---|
| "when `ENFORCE_IP_ALLOWLIST=true`, only Tier2's two IPs (via `CF-Connecting-IP`) may reach the Halo mock" | **Partially true** | Mechanism works and the header is CF-trusted, but it is fail-open when the var ≠ `"true"` and is the *only* control (F1/F2). `src/tier2.ts:8` |
| "`/admin/sync` requires `ADMIN_KEY`" | **Confirmed** (non-constant-time, F6) | `src/index.ts:20,95-102` |
| "The optional Halo OAuth credentials … are validated at `/token` when set" | **True but misleading** | Literally validated at issuance (`src/halo.ts:176-180`), but the issued token is never checked afterward, so it protects nothing on the data/create endpoints (F1) |
| "Secrets are CLI-only — never in code or `wrangler.toml`" | **Confirmed** | `wrangler.toml` holds only ids/config + `database_id`; history clean |
| "The Gorelo key is never logged" | **Confirmed** | Key only ever sent as the outbound `X-API-Key` header (`src/gorelo.ts:39`); never printed. `safeHeaders` redacts inbound `authorization`/`cookie`; error paths log `err.body`/`message`, not request headers |

Also verified (README body, not §Security): "always returns decodable JSON even
on error" — **Confirmed** (`src/halo.ts:1128-1131`); "on a Gorelo create failure
`/actions` returns 502" — **Confirmed** (`:951-953`), and a failed create is not
turned into a 200 success.

---

## 5. Prioritized remediation plan

**Before the next deploy (must):**
1. **F2** — make `ipAllowed` fail-closed and case-insensitive (small, contained;
   removes the single most dangerous failure mode). 
2. **F1** — either enforce a real (HMAC-signed) token on every non-`/token` Halo
   endpoint, or, if Tier2's client can't round-trip it, make the IP allowlist
   mandatory (refuse to serve when neither IP allowlist nor OAuth is active) and
   correct the README so OAuth is not presented as a data-endpoint control.
3. **F3** — stop logging `err.body` ungated and stop returning `String(err)` in
   the 500 body; replace with a `request_id` breadcrumb.

**Soon (should):**
4. **F4** — single logging chokepoint; drop `hostname` from the always-on routing
   line; make a deliberate decision on `invocation_logs`.
5. **F6** — constant-time `ADMIN_KEY` compare.

**Backlog (nice to have):**
6. **F7** — rate limiting on `/tickets` and `/admin/sync`; cap `pending_tickets`.
7. **F5** — tighten request-supplied `user_id` vs report-derived client.
8. **F8** — scrub notifly error strings before logging.

---

## 6. What I could not verify

- **`@ambersecurityinc/notifly` internals** — not installed here; whether its
  per-destination `error` string echoes the destination URL / `sig` token (F8),
  and its exact outbound behavior for `workflows://`/`jsons://` schemes.
- **External Gorelo API behavior** — whether `POST /v1/tickets` error responses
  echo submitted field values (bears on the severity of F3's `err.body` leak),
  and the real int→label mappings for priority/source/status.
- **Cloudflare platform guarantees** — that `CF-Connecting-IP` is always
  overwritten by the edge for this Worker's routes (documented behavior, assumed
  true); D1 `RETURNING`/`ON CONFLICT` atomicity semantics under concurrency; and
  Workers Logs / invocation-log retention and access scope.
- **Runtime secret values** — actual `GORELO_API_KEY`, `ADMIN_KEY`,
  `NOTIFLY_URLS`, and whether `ENFORCE_IP_ALLOWLIST`/`DEBUG_LOGS` are `"true"` in
  the live deployment (reviewed against the committed `wrangler.toml` defaults
  only).
- **`npm audit` against a live advisory DB** — no registry access; assessed the
  lockfile statically (1 runtime dep, 0 transitive deps, all registry-resolved
  with integrity hashes, no git/http sources). `renovate.json` auto-merges only
  **lock-file maintenance** (not version bumps), which is low-risk.

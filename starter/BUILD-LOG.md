# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

### 2026-09-27 · Phase 1 — verifyAccessToken green (43/43)

Expected the payload-swap case to fail on payload validation. It fails earlier, on the
signature check — the tampered payload never reaches claim validation, which is the point.
Also almost missed that `exp == now` is expired (half-open, `<=`, not `<`), and that `jti`
needs a non-empty-string check, not just presence. Fixed in `starter/server/auth.js`.
Note: `pv`/staleness lives in `assertFresh`, not in the verifier; refresh-vs-access falls
out of the 3-segment + JSON + HS256-pinned parse. `node scripts/check-jwt.js` is ALL PASS.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

### 2026-09-27 · Phase 2 — buildContext drafted, reviewed, verified (15/15)

Started assuming `authenticate(db, secret)` ran once at startup, so the `db.prepare()` sat
inside it. Review caught it: `server/index.js:50` calls the outer function per request, so
that was one SQL recompile per authenticated request. Moved the statement to module scope
with `??=` — compiled once, results never cached, so no staleness question (`context.js`).
Also dropped the `params.org ?? params.orgId` hedge for plain `params.org`: `router.js`
populates keys from the `:name` in the pattern I register, so the fallback could only ever
mask a misnamed param into silently skipping the 404 isolation check. Convention fixed now:
org routes use `:org` (Phase 3 must follow it).
Suspended passes through with a valid caller (`resolve()` denies all, reason `suspended`);
removed/invited/no-row are 401. Verified with a throwaway stub-db harness (15 cases:
header shapes, cross-org 404, stale pv, role-from-row) — real-DB check still blocked on
the better-sqlite3 build-tools issue. Harness deleted after the run.

### 2026-09-27 · Phase 2 — resolve() status-branches slice (17/17)

No nvm in this environment and no MSVC tools, so Node stays 24 and real-DB testing
stays blocked — stub-db harness again (deleted after the run). Slice covers Q1 + Q2
only: fresh membership lookup per call (required, not wasteful — `resolve()` takes bare
IDs, so it cannot borrow context.js's copy), catalogue read from `permissions` (overlay
permission `widget:frobnicate` in the harness proves nothing is hardcoded), three status
branches returning `{ role, permissions }` with `denyAll` maps. Active branch still throws
`NOT_IMPLEMENTED` — that's the slice boundary, asserted in the harness, next commit.
Deliberately no per-db statement cache yet: `resolve()` receives `db` per call (unlike
`authenticate()`, which captures it once), so caching would need a WeakMap keyed by db —
deferring that to the `resolveDevices` slice, where per-device prepare-sharing actually
matters for the §6 "one query per row" rule. `toIsoUtc(now)` normalizes up front so the
grants query's double-`now` binding (next slice) can never receive two formats.

### 2026-09-27 · Env unblocked: portable Node 22 + load-db.js Windows fix

No nvm here, so per the portable suggestion: downloaded Node v22.23.3 Windows binary
zip (no install, no admin), prepended to PATH per-shell (`C:\Users\kruth\tools\`).
`npm install` in `starter/` then finished in 4s off the prebuilt binary — no compilation.
Two Windows-hostile bits in given plumbing: `npm run db:reset` uses `rm -f` (ran the
equivalent manually instead — did NOT edit package.json), and `scripts/load-db.js:10`
used `new URL(...).pathname`, which yields `/C:/...` on Windows and ENOENTs. Fixed with
`fileURLToPath` (cross-platform safe, one line + import). Real DB now seeded: 3 orgs,
20 permissions, overlay fingerprint bb339819425c (reviewer role, `device:reboot`).

### 2026-09-27 · Phase 2 — resolve() device-level slice, real-DB harness 17/17

Q3 + baselines + deny-first + wildcards + windows in one slice — windows/wildcards rode
along because the fetch is a single query and testing half of a WHERE clause would prove
nothing. Named params (`@now`) for the double-`now` bind; `matchesPattern` derives the
resource from the pattern string, so `device:reboot` matches `device:*` with no special
case. Verified against real app.db (rolled-back tx for inserts): all §11 vectors,
D1 carve-out, `device:*` boundaries, expired/future inert, overlay allow+deny pair.
`void at/deviceId` markers removed now they're wired; org-level (`deviceId null`) still
throws `NOT_IMPLEMENTED` — next slice is Q4 + union.

### 2026-09-27 · Phase 2 — org union + resolveDevices, check-permissions 32/35

Refactored to `loadInputs` (Q1+Q2+Q3 once) + `evaluateScope(deviceId|null)` + `mergeOrgLevel`,
so `resolve()` and `resolveDevices()` share one fetch — list endpoints pay Q1/Q2/Q3 once
however many rows render. Union is allow-wins with source precedence role > org-wide
grant > first allowing device (sorted ids, deterministic). check-permissions.js: 32/35 —
every resolve-scope case green including g_carve, wildcards, windows, suspended; the 3
failures are all `assertCanStartSession`, still stubbed, next slice. check-personalisation
18/18. Spot harness (deleted after): batched==single per device, union semantics on real
fixture + overlay (robin reboot allow at org, deny on dev_b row), suspended/no-member
batched branches. No Q3 behavior touched — device-level code moved verbatim into
evaluateScope.

### 2026-09-27 · Phase 2 — delegates slice, check-permissions 35/35

`can`/`assertCan`/`assertMayGrant`/`assertCanStartSession` as pure consumers: one
`resolve()` each, zero new resolution logic, `evaluateScope`/`loadInputs` untouched
(the prior 32 cases passing unchanged is the proof). Two ordering decisions: compound
check reads `session:start` first so missing-both reports `missing_permission` (a caller
who can't open sessions at all has a different problem than one refused on one device);
`assertMayGrant` expands each pattern against the live catalogue and requires holding
EVERY covered permission, so `device:*` can't launder one unheld perm. Self-grant
rejection stays out — the signature never sees the target user; Phase 4 route's job.
Also: deliberately not two `assertCan()` calls inside the compound check (two fetches,
wrong reason strings). Full board: 35/35 permissions, 18/18 personalisation, 43/43 jwt,
zero `todo(` refs. Reviewed against the §9 contract and approved.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

### 2026-09-27 · Phase 3 — lifecycle.js + audit.js, harness 36/36 (reviewed, approved)

Seven lifecycle helpers + two audit helpers, verified on real app.db / :memory: with a
throwaway harness (deleted after). Two reds were both harness bugs, implementation
untouched: (1) seeded live session `ses_live_build_server` inflated my end-count —
forgot the fixture has an active sam session, rescoped the assertion to device level;
(2) empty `:memory:` tripped the `actor_id` FK and masked the rethrown denial error —
real routes always have an authenticated actor, seeded a minimal user row instead.
Reconciliation worth keeping: §6 "equal role → 403" vs check-api:150 owner-demotes-owner
→ 200. Resolved as owners-bypass-rank + explicit confer-owner rule (not emergent from
rank values), route calls it for current and new role. Ranks/roles read from tables
(reviewer 35 outranks operator 30 in-harness — no hardcoded matrix). auditDenials logs
403 only: 404 is invisibility, and logging it would write an existence oracle into a log
`audit:read` holders can read. Full board still green: 35/35, 18/18, 43/43.

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

### 2026-09-27 · Phase 3 — auth routes slice, HTTP harness 22/22 (reviewed, approved)

`POST /auth/login|refresh|token` + `GET /auth/me`, all on top of existing primitives —
no parallel permission logic (`/me` permissions come straight from `resolve()`).
check-api auth sections green; the `no-token→401` 404 is a pipeline artifact (index.js
404s unmatched routes before auth runs) that vanishes when devices routes land.
Caught live during verification: first `/auth/token` draft 404'd unknown orgs → changed
to one membership lookup, unknown and non-member both 401, so the endpoint never tells
a caller which org ids exist. Refresh rows carry no org (schema, D12) → refresh mints
for the login-default org; replay of a rotated token kills the whole family including
the successor (verified). Default org = highest rank among active memberships.

### 2026-09-27 · Phase 3 — orgs group, HTTP harness 14/14 (reviewed, approved)

`GET/POST /v1/orgs`, `PATCH/DELETE /v1/orgs/:org`, sharing auth.js `activeOrgs`
helpers. Soft-delete (`deleted_at` — hard delete would trip member FKs and orphan
audit history) plus `assertOrgLive` 404-first on `:org` routes, because a token
outlives its org's deletion (context checks membership, not the org row). Default
theme cycles a fixed palette by live-org count — sequential creates differ;
explicit theme honored and validated. Integration catch fixed in-slice: soft-deleted
org still minted via `/auth/token` (membership check lacked the org-liveness join);
now unknown/non-member/deleted all 401 through one lookup, no existence branch.
check-api org assertions green (create sole-owner, D18 404); no-token-401 and the
devices abort are pipeline artifacts pending the devices group.

`POST /auth/login|refresh|token` + `GET /auth/me`, all on top of existing primitives —
no parallel permission logic (`/me` permissions come straight from `resolve()`).
check-api auth sections green; the `no-token→401` 404 is a pipeline artifact (index.js
404s unmatched routes before auth runs) that vanishes when devices routes land.
Caught live during verification: first `/auth/token` draft 404'd unknown orgs → changed
to one membership lookup, unknown and non-member both 401, so the endpoint never tells
a caller which org ids exist. Refresh rows carry no org (schema, D12) → refresh mints
for the login-default org; replay of a rotated token kills the whole family including
the successor (verified). Default org = highest rank among active memberships.

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._

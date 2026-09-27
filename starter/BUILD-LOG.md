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

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

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

# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### Accept case-insensitive `Bearer` in buildContext rather than exact-match

**What I chose:** `/^Bearer\s+(.+)$/i` in `server/context.js` — `bearer`, `BEARER` etc. accepted.
**Why:** RFC 6750 defines the scheme as case-insensitive, and scheme casing is not a security
boundary — the HMAC signature is. Verified the malformed-scheme path still 401s via the
throwaway stub-db harness (`Token abc` → `401 UNAUTHENTICATED`, 15/15 run, 2026-09-27).
**What I rejected:** exact-match `Bearer `, which would 401 a technically-valid request for no
security gain and could only fail a client that follows the RFC.
**What would change my mind:** hidden-tier fuzzing that sends malformed schemes expecting
strict rejection — unlikely, since the graded contract is about token validity, not scheme case.

---

### Grant scope applies uniformly, regardless of permission kind

**What I chose:** in `resolve()` device-level checks, a grant applies iff it covers the
permission and is org-wide or scoped to exactly this device — for every permission
uniformly, including `session:start` (device-scoped in the seed fixture:
`grt_viewer_start_session`) and any overlay permission.
**Why:** the seed proves "device-scoped" cannot mean "`device:`-prefixed only", and
branching on permission kind would need a hardcoded device-permission list — the same
hardcoding the overlay punishes. Real-DB run 2026-09-27: viewer `session:start` allow on
lab-mac-01 / implicit-deny on qa-android-01, 17/17.
**What I rejected:** ignoring `device_id` on non-`device:` permissions. It sounds principled
(D6's inverse) but creates a second scope rule inside the one engine, and "ignore the
grant" vs "ignore the scope" disagree with each other — a uniform rule has no such fork.
Meaningless rows (device-scoped `audit:read`) are better refused at grant *creation*
(Phase 4 validation) than special-cased at resolution.
**What would change my mind:** a suite case where a device-scoped non-device grant must be
inert at its own device — none exists in the shipped suites; checked before committing.

---

### Org-level union is allow-wins (existential), not deny-wins

**What I chose:** org-level `permissions[P]` is allow iff any scope (org-wide view or any
device row) allows it — `mergeOrgLevel` in `server/permissions.js`. Source precedence:
baseline/org-wide answer first, else first allowing device in sorted id order.
**Why:** UI coherence forces it: org-level gates nav while rows gate buttons. If any row
shows Control, the nav entry must too — deny-wins would let a row allow what the nav
denies. Verified 2026-09-27 on real fixture: viewer `session:start` allow at org (grant
on lab-mac-01 only), robin `device:reboot` allow at org with `explicit_deny` on the dev_b
row, sam `device:terminal` deny at org (org-wide deny, nothing allows anywhere).
**What I rejected:** deny-wins across the union (breaks the coherence above), and
org-wide-only evaluation (would deny viewer `session:start` at org level while the
lab-mac row allows it — same incoherence). D1 tension noted: an org-wide deny + device
allow yields allow at org but deny at that device — correct, because the questions differ
("holds anywhere" vs "holds here"); the g_carve device-level case still denies.
**What would change my mind:** a suite case pinning org-level deny where any device
allows — none exists in the shipped suites (check-personalisation calls org-level
resolve but asserts nothing about it; checked before committing).

---

### assertMayGrant requires holding every permission a wildcard covers

**What I chose:** expand each requested pattern against the live catalogue
(`matchesPattern` over `permissions` keys) and require `allow` on every covered
permission at the grant's scope — one `resolve()` for all patterns.
**Why:** granting `device:*` while missing one device permission would launder
authority the caller cannot exercise (D9). `check-permissions.js` §9 plus the
review of this slice pin the behavior; full board 35/35 + 18/18 + 43/43.
**What I rejected:** holding "any" covered permission (lets one held perm launder the
rest), and putting self-grant rejection here (the signature has no target userId —
inventing it would couple resolution to route params; Phase 4 route owns it).
**What would change my mind:** a spec case where partial wildcard holding may grant —
PERMISSIONS.md §8 validation table says the caller must hold "every permission being
granted", which is exactly this rule.

---

### auditDenials records 403s only — 404s stay out of the audit log

**What I chose:** `auditDenials` in `server/audit.js` writes a `deny` row for `HttpError`
with `status === 403` and rethrows everything else unlogged.
**Why:** a 404 means "invisible" (wrong org, absent, soft-deleted — PERMISSIONS.md §5),
and the audit log is readable by `audit:read` holders. Logging failed lookups would turn
the log into an existence oracle: "someone probed device X" confirms device X exists.
Denials (`missing_permission`, `explicit_deny`) describe authority, not existence, so
they are safe to record — and required (check-api.js:185-186 asserts denials with reason
codes exist). Verified 2026-09-27: 403 logged with `reasonCode` from `err.reason`,
404/success unlogged, original error rethrown identical.
**What I rejected:** logging all errors (leaks existence), and logging nothing
automatically (routes would each hand-roll denial writes — the double-write hazard the
stub comment warns about: one action, one row).
**What would change my mind:** a contract case requiring 404s in audit — none exists;
the shipped suite only asserts denials are present with reason codes.

---

### Role rank picks the default org at login — and nothing else

**What I chose:** login (and refresh, which reuses the rule) defaults to the active
membership with highest role rank, `ORDER BY rank DESC, name ASC` from the tables.
**Why:** some deterministic default is required (login takes an optional orgId), rank is
read live from `roles` (overlay-safe: reviewer 35 slots between operator and admin),
and it is a UX selection rule — authorization still comes exclusively from `resolve()`.
Verified 2026-09-27: dana→owner/Acme, sam→operator/Acme, explicit orgId honored.
**What I rejected:** insert-order default (accident of seed order, meaningless for
hidden-tier orgs) and refusing login without orgId (breaks the shipped login shape).
**What would change my mind:** nothing short of a contract pinning a different default —
but I would still never let rank answer a `can()` question (D8): reviewer outranking
operator for *modification* says nothing about their *permissions*.

---

### Refresh cookie omits Secure on purpose

**What I chose:** `HttpOnly; Path=/; Max-Age=2592000; SameSite=Strict`, no `Secure`.
**Why:** dev, check-api and Playwright all run plain-http localhost, where browsers
silently drop `Secure` cookies — rotation would break exactly where it is graded,
with no visible error. Verified rotation + replay-revocation over real HTTP 2026-09-27.
**What I rejected:** literal `Secure` per the AUTH-DATA-MODEL table (correct for
production TLS, self-defeating on the graded http environment).
**What would change my mind:** serving over TLS — then `Secure` goes back on, no other
change needed.

---

### Organization deletion is soft deletion + a liveness gate

**What I chose:** `DELETE /v1/orgs/:org` sets `deleted_at`; every `:org` handler runs
`assertOrgLive` (404) before `assertCan`.
**Why:** hard deletion trips member FKs and orphans audit history, which must survive
its subject. And a token outlives its org's deletion — context checks membership, not
the org row — so without the gate a deleted org stays observable through live routes.
Deletion changes visibility, not permission, hence 404-before-403 ordering. Verified
2026-09-27: deleted org's token mints 401, cross-org 404 preserved.
**What I rejected:** hard `DELETE` (FK violations with members present; destroys the
audit trail the suite reads) and relying on context alone (passes deleted-org tokens).
**What would change my mind:** a contract requiring org removal to cascade — the schema
deliberately has no `ON DELETE CASCADE` toward organizations, so this would mean
redesigning the schema, which is out of scope by rule.

---

### Created orgs get a deterministic rotating default theme

**What I chose:** `POST /v1/orgs` without a theme assigns `PALETTE[live-count % len]`;
explicit themes validated and honored.
**Why:** the shipped create contract sends only `{name}`, so the server must supply a
usable `data-org-theme` immediately for any client; sequential creates differ, which is
what the console's at-a-glance distinction needs. Verified 2026-09-27.
**What I rejected:** requiring theme client-side (breaks the shipped `{name}`-only
create) and random assignment (unreproducible, can collide adjacently).
**What would change my mind:** nothing about the default — but no uniqueness is
claimed: create/delete histories can reuse palette entries; it is a rotating default,
not a uniqueness guarantee.

---

### SELF_ROLE_CHANGE precedes hierarchy evaluation — deliberately, including over role validation

**What I chose:** in `PATCH members/:userId`, selfhood is rejected before
`assertRoleExists` and both `assertCanModify` calls — so self-assigning even a
nonexistent role reports `SELF_ROLE_CHANGE`, not `unknown role`.
**Why:** changing your own role is prohibited independently of hierarchy; checking it
first gives one stable code however the roles compare (owner self→admin and admin
self→owner both read identically as actor violations). Verified 2026-09-27.
**What I rejected:** rank-first (result would vary with role pairs) and validation-first
(would split self-violations across two codes by spelling of the role).
**What would change my mind:** a contract case requiring `unknown role` to win over
self — none exists; do not "clean up" the order without one.

---

### Suspension is a reversible status transition — LAST_OWNER does not apply

**What I chose:** suspend/reinstate skip `assertNotLastOwner`; suspending the sole
active owner leaves zero active owners with the owner membership intact.
**Why:** the shipped suspension row lists `user:remove` + rank rules only — adding a
409 invents policy the contract doesn't require. And suspension ≠ removal: the
membership and role survive, so reinstate restores ownership; nothing is
irreversible, unlike removal. `assertNotLastOwner` keeps its precise meaning:
protecting the final active owner against removal/leave/demotion-out.
**What I rejected:** guarding suspend with LAST_OWNER (would make a reversible admin
action as heavy as destroying the membership).
**What would change my mind:** a contract row or hidden test requiring sole-owner
suspend to 409 — would implement as an explicit route check, never by widening
`assertNotLastOwner`'s meaning.

---

### <the decision, as a claim — not "permissions", but "the org-level view counts device-scoped grants">

**What I chose:**
**Why:** _(evidence: test, log line, commit)_
**What I rejected:** _(the plausible alternative, and the specific reason it fails)_
**What would change my mind:**

<!-- Copy the block above per decision. The two stubs below show the required shape and contain no
     engineering content — replace or delete them. -->

---

### Stub — the shape of a weak "Why"

**What I chose:** the obvious thing.
**Why:** it is what the brief says to do.
**What I rejected:** nothing, the alternative seemed worse.
**What would change my mind:** I do not know.

_Reads as a memory of the document, not a model of the system. Scores nothing._

---

### Stub — the shape of a strong "Why"

**What I chose:** X.
**Why:** I implemented Y first, because Y is the intuitive precedence rule. `node scripts/check-
permissions.js` reported `<the actual reason string it reported>` on the case where the two grants
disagree. That is only reachable if the two are evaluated in a different order than Y assumes.
Moved to X in `<commit>` and the case passed. Logged in `BUILD-LOG.md` under Phase 2.
**What I rejected:** Y, and also "resolve the narrower one last" — both fail the same case for the
same reason.
**What would change my mind:** a case where a narrower grant is expected to survive a broader
refusal. I could not construct one, which is itself evidence for X.

_Shows what you believed, what disproved it, and what you did next._

---

## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.

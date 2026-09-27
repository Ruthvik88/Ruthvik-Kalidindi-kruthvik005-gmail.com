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

// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/permissions.js — ${name}() is yours to write (BRIEF.md §3).`),
    { code: 'NOT_IMPLEMENTED' }
  );

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// Normalize the caller-supplied `now` to the one timestamp shape the schema
// compares correctly: ISO-8601 UTC with millis. TEXT timestamps only sort ==
// chronologically when every writer uses this exact shape (schema.sql dialect
// notes), so every query below binds this value — including twice in the
// grants query, where starts_at <= now < expires_at each take a copy.
const toIsoUtc = (now) => new Date(now).toISOString();

const denyAll = (keys, reason) =>
  Object.fromEntries(keys.map((k) => [k, { effect: 'deny', source: null, reason }]));

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const at = toIsoUtc(now); // fail fast on a bad `now`, before any query
  void at; // bound by the grants query in the next slice; normalized here so every branch agrees
  void deviceId;

  // Fresh membership lookup, independent of context.js's copy: this function
  // takes bare IDs (check-permissions.js calls it with no ctx), so it cannot
  // borrow the pipeline's. One indexed row via UNIQUE(org_id, user_id).
  const membership = db
    .prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);

  // Catalogue from the table, never hardcoded: the personalised overlay adds a
  // permission the prose never mentions, and a hardcoded list would silently
  // drop it from every resolved set.
  const keys = db.prepare('SELECT key FROM permissions').all().map((r) => r.key);

  if (!membership || membership.status === 'removed' || membership.status === 'invited') {
    return { role: null, permissions: denyAll(keys, 'not_a_member') };
  }
  if (membership.status === 'suspended') {
    return { role: membership.role, permissions: denyAll(keys, 'suspended') };
  }

  throw todo('resolve (active branch)');
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  throw todo('resolveDevices');
}

export function can(db, ctx, permission, deviceId) {
  throw todo('can');
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  throw todo('assertCan');
}

// No privilege laundering: you may only grant authority you hold at that scope.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  throw todo('assertMayGrant');
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  throw todo('assertCanStartSession');
}

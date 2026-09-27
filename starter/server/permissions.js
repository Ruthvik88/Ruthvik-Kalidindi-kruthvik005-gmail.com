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

// A grant pattern covers a permission if it names it exactly, names its
// resource wildcard ('device:*' covers 'device:control'), or is the global
// wildcard. The resource prefix comes from the pattern itself, so permissions
// the prose never mentions (personalisation overlay) match with no special case.
const matchesPattern = (permission, pattern) => {
  if (pattern === '*') return true;
  if (pattern.endsWith(':*')) return permission.startsWith(pattern.slice(0, -1));
  return permission === pattern;
};

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const at = toIsoUtc(now); // fail fast on a bad `now`, before any query

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

  if (deviceId === null) throw todo('resolve (org-level branch)');

  // --- device-level resolution for one device, active memberships -----------
  const baseline = new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(membership.role).map((r) => r.permission)
  );

  // One fetch for every grant that could apply: this user, this org, live
  // (revoked_at IS NULL hits grants_for_resolution), window half-open
  // (starts_at <= now < expires_at, so expires_at == now is expired — D7).
  // Named params so the two `now` bindings cannot be transposed. Scope is
  // partitioned in JS below, so this same fetch serves the org-level slice.
  const grantRows = db
    .prepare(
      `SELECT g.id, g.device_id, g.effect, gp.permission AS pattern
         FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
        WHERE g.user_id = @userId AND g.org_id = @orgId AND g.revoked_at IS NULL
          AND (g.starts_at IS NULL OR g.starts_at <= @now)
          AND (g.expires_at IS NULL OR g.expires_at > @now)`
    )
    .all({ userId, orgId, now: at });

  const permissions = {};
  for (const key of keys) {
    // A grant applies here if it covers the permission (exact or wildcard)
    // and is org-wide or scoped to exactly this device. Scope is uniform
    // across permission kinds: session:start grants are device-scoped in the
    // seed fixture, so "device-scoped" cannot mean "device:-prefixed only".
    const applicable = grantRows.filter(
      (g) => matchesPattern(key, g.pattern) && (g.device_id === null || g.device_id === deviceId)
    );

    // D1: deny wins regardless of scope — an org-wide deny is visible here
    // before any device-scoped allow, so carve-outs cannot happen.
    const deny = applicable.find((g) => g.effect === 'deny');
    if (deny) {
      permissions[key] = { effect: 'deny', source: `grant:${deny.id}`, reason: 'explicit_deny' };
      continue;
    }
    if (baseline.has(key)) {
      permissions[key] = { effect: 'allow', source: `role:${membership.role}`, reason: null };
      continue;
    }
    const allow = applicable.find((g) => g.effect === 'allow');
    if (allow) {
      permissions[key] = { effect: 'allow', source: `grant:${allow.id}`, reason: null };
      continue;
    }
    permissions[key] = { effect: 'deny', source: null, reason: 'implicit' };
  }

  return { role: membership.role, permissions };
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

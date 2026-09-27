// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

import { forbidden, badRequest, lastOwner } from './http.js';
import { nowIso } from './db.js';

// Modification ranks, read from the table — never hardcoded. The personalised
// overlay adds a role with its own rank, so a literal map would mis-order it.
export function roleRanks(db) {
  return Object.fromEntries(db.prepare('SELECT key, rank FROM roles').all().map((r) => [r.key, r.rank]));
}

export function assertRoleExists(db, role) {
  if (!roleRanks(db)[role]) throw badRequest(`unknown role ${role}`);
}

// May a caller with callerRole modify a user holding (or being assigned)
// targetRole? Owners may modify anyone; everyone else needs a strictly greater
// rank — admin→admin is 403, but owner→owner demotion is allowed (the shipped
// suite demotes a non-last owner to viewer). Conferring owner needs ownership
// itself, stated explicitly rather than relying on owner holding the top rank.
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  if (!ranks[callerRole] || !ranks[targetRole]) throw badRequest(`unknown role ${callerRole} / ${targetRole}`);
  if (targetRole === 'owner' && callerRole !== 'owner') {
    throw forbidden('only an owner may confer owner');
  }
  if (callerRole !== 'owner' && !(ranks[callerRole] > ranks[targetRole])) {
    throw forbidden(`${callerRole} cannot modify ${targetRole}`);
  }
}

// The org must always have at least one owner. Call before removing, demoting,
// suspending(?) or letting leave a membership: no-op unless the target is
// currently an active owner, then throw 409 LAST_OWNER if none would remain.
// Suspended owners cannot act, so they don't count toward the quorum.
export function assertNotLastOwner(db, orgId, userId) {
  const me = db
    .prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);
  if (!me || me.role !== 'owner' || me.status !== 'active') return;
  const remaining = db
    .prepare("SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'")
    .get(orgId).n;
  if (remaining <= 1) throw lastOwner();
}

// End active sessions matching the given tenancy filters. Permission tweaks
// never call this (grandfathering); suspension, removal and device transfer do.
// Any filter may be omitted; exceptSessionId spares one session. Returns the
// number of sessions ended.
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const conds = ["state = 'active'"];
  const params = [];
  if (orgId !== undefined) {
    conds.push('org_id = ?');
    params.push(orgId);
  }
  if (userId !== undefined) {
    conds.push('user_id = ?');
    params.push(userId);
  }
  if (deviceId !== undefined) {
    conds.push('device_id = ?');
    params.push(deviceId);
  }
  if (exceptSessionId !== undefined) {
    conds.push('id != ?');
    params.push(exceptSessionId);
  }
  return db
    .prepare(`UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE ${conds.join(' AND ')}`)
    .run(reason, nowIso(), ...params).changes;
}

// The authorization snapshot a session carries for life (PERMISSIONS.md §7.1):
// the role plus the ids of the live ALLOW grants at this scope, frozen with a
// timestamp. Denies authorize nothing, so they are not recorded.
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const membership = db
    .prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);
  const at = nowIso();
  const grantIds = db
    .prepare(
      `SELECT id FROM grants
        WHERE user_id = ? AND org_id = ? AND effect = 'allow' AND revoked_at IS NULL
          AND (device_id IS NULL OR device_id = ?)
          AND (starts_at IS NULL OR starts_at <= ?)
          AND (expires_at IS NULL OR expires_at > ?)
        ORDER BY id`
    )
    .all(userId, orgId, deviceId, at, at)
    .map((r) => r.id);
  return { role: membership?.role ?? null, grantIds, snapshotAt: at };
}

// A session lives at most max_session_minutes past its start (default 60),
// which is what bounds grandfathering: revoked authority dies with the TTL.
export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  const startedAt = nowIso();
  const expiresAt = new Date(Date.now() + (org?.max_session_minutes ?? 60) * 60000).toISOString();
  return { startedAt, expiresAt };
}

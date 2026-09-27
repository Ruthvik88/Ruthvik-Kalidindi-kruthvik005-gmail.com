// Session routes: start (compound check), list, read, stop. Shapes follow
// BRIEF.md §5.1; lifecycle rules (grandfathering, exclusivity, TTL) come from
// PERMISSIONS.md §7 and lifecycle.js.

import { send, badRequest, notFound, deviceBusy } from '../http.js';
import { assertCan, assertCanStartSession } from '../permissions.js';
import { snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { nowIso, newId } from '../db.js';

const assertOrgLive = (db, orgId) => {
  const row = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!row) throw notFound('org not found');
};

const targetDevice = (db, orgId, deviceId) => {
  const row = db
    .prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL')
    .get(deviceId, orgId);
  if (!row) throw notFound('device not found');
};

// TTL is enforced lazily: any read path retires active sessions past
// expires_at first, so expiry never depends on a background job. One UPDATE,
// no per-row queries.
const expireDueSessions = (db) => {
  db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = 'session_expired', ended_at = ?
      WHERE state = 'active' AND expires_at <= ?`
  ).run(nowIso(), nowIso());
};

const sessionRow = (db, id) => {
  const row = db
    .prepare(
      `SELECT id, org_id AS orgId, user_id AS userId, device_id, mode, state,
              end_reason, authorized_by, started_at, expires_at, ended_at
         FROM sessions WHERE id = ?`
    )
    .get(id);
  if (!row) return null;
  return { ...row, authorized_by: JSON.parse(row.authorized_by) };
};

export function registerSessionRoutes(router, { db, secret }) {
  void secret;

  // POST /v1/orgs/:org/sessions — session:start AND the mode permission, both
  // on the device (assertCanStartSession keeps the two refusals distinct).
  // Control/terminal are exclusive per device (D10): the second concurrent
  // INSERT loses at the partial unique index — no check-then-act race — and
  // the loser gets 409 naming the holder. View is never exclusive.
  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    let createdId = null;
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'session.start', targetType: 'session', targetId: null },
      async () => {
        assertOrgLive(db, ctx.orgId);
        const { deviceId, mode } = ctx.body ?? {};
        if (!deviceId || typeof deviceId !== 'string') throw badRequest('deviceId is required');
        targetDevice(db, ctx.orgId, deviceId);
        assertCanStartSession(db, ctx, mode, deviceId);
        const snapshot = snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
        const { startedAt, expiresAt } = sessionExpiry(db, ctx.orgId);
        const id = newId('ses');
        try {
          const tx = db.transaction(() => {
            // Retire TTL-past sessions inside the same transaction: an expired
            // exclusive holder must not 409 a new session merely because no
            // read has run the cleanup yet. Exclusivity itself still rests on
            // the partial unique index (concurrency), not on this pass.
            expireDueSessions(db);
            db.prepare(
              `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
               VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
            ).run(id, ctx.orgId, ctx.userId, deviceId, mode, JSON.stringify(snapshot), startedAt, expiresAt);
            audit(db, {
              orgId: ctx.orgId,
              actorId: ctx.userId,
              action: 'session.start',
              targetType: 'session',
              targetId: id,
              result: 'allow',
              reasonCode: null,
              requestId: ctx.requestId,
            });
          });
          tx();
        } catch (err) {
          if (err?.code !== 'SQLITE_CONSTRAINT_UNIQUE') throw err;
          const holder = db
            .prepare(
              `SELECT id FROM sessions WHERE device_id = ? AND state = 'active'
                AND mode IN ('control','terminal') ORDER BY started_at ASC LIMIT 1`
            )
            .get(deviceId);
          throw deviceBusy(
            holder
              ? `device already has an exclusive session (${holder.id})`
              : 'device already has an exclusive session'
          );
        }
        createdId = id;
      }
    );
    send(res, 201, sessionRow(db, createdId));
  });

  // GET /v1/orgs/:org/sessions — session:view, most recent first.
  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    assertOrgLive(db, ctx.orgId);
    assertCan(db, ctx, 'session:view', null);
    expireDueSessions(db);
    const rows = db
      .prepare(
        `SELECT id, org_id AS orgId, user_id AS userId, device_id, mode, state,
                end_reason, authorized_by, started_at, expires_at, ended_at
           FROM sessions WHERE org_id = ? ORDER BY started_at DESC, id DESC`
      )
      .all(ctx.orgId)
      .map((r) => ({ ...r, authorized_by: JSON.parse(r.authorized_by) }));
    send(res, 200, { sessions: rows });
  });

  // GET /v1/sessions/:id — participant (any org token: same user) or
  // session:view in the session's org. Cross-org strangers 404, same-org
  // strangers without the permission 403.
  router.get('/v1/sessions/:id', async (ctx, params, res) => {
    expireDueSessions(db);
    const found = db.prepare('SELECT id, org_id AS orgId, user_id AS userId FROM sessions WHERE id = ?').get(params.id);
    if (!found) throw notFound('session not found');
    if (found.userId !== ctx.userId) {
      if (found.orgId !== ctx.orgId) throw notFound('session not found');
      assertCan(db, ctx, 'session:view', null);
    }
    send(res, 200, sessionRow(db, params.id));
  });

  // DELETE /v1/sessions/:id — the session's owner ends it (user_stopped), or
  // anyone with session:terminate (admin_terminated). Same visibility ladder
  // as the read path. Idempotent: ending an ended session returns its row.
  router.delete('/v1/sessions/:id', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'session.stop', targetType: 'session', targetId: params.id },
      async () => {
        const found = db.prepare('SELECT id, org_id AS orgId, user_id AS userId FROM sessions WHERE id = ?').get(params.id);
        if (!found) throw notFound('session not found');
        let reason = 'user_stopped';
        if (found.userId !== ctx.userId) {
          if (found.orgId !== ctx.orgId) throw notFound('session not found');
          assertCan(db, ctx, 'session:terminate', null);
          reason = 'admin_terminated';
        }
        const tx = db.transaction(() => {
          db.prepare(
            `UPDATE sessions SET state = 'ended', end_reason = COALESCE(end_reason, ?), ended_at = COALESCE(ended_at, ?)
              WHERE id = ? AND state = 'active'`
          ).run(reason, nowIso(), params.id);
          audit(db, {
            orgId: found.orgId,
            actorId: ctx.userId,
            action: 'session.stop',
            targetType: 'session',
            targetId: params.id,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 200, sessionRow(db, params.id));
  });
}

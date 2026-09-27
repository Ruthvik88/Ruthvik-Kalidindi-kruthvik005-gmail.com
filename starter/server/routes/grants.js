// Grant routes: create, list, revoke. Validation follows AUTH-DATA-MODEL.md §8
// exactly — the table there is the contract, including its error codes.

import { send, badRequest, notFound, forbidden, normalizeTs, HttpError } from '../http.js';
import { assertCan, assertMayGrant } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { nowIso, newId, bumpPermVersion } from '../db.js';

const assertOrgLive = (db, orgId) => {
  const row = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!row) throw notFound('org not found');
};

const grantShape = (db, id) => {
  const g = db
    .prepare(
      `SELECT id, org_id AS orgId, user_id AS userId, device_id AS deviceId, effect,
              starts_at AS startsAt, expires_at AS expiresAt, revoked_at AS revokedAt,
              created_by AS createdBy
         FROM grants WHERE id = ?`
    )
    .get(id);
  if (!g) return null;
  g.permissions = db.prepare('SELECT permission FROM grant_permissions WHERE grant_id = ? ORDER BY permission').all(id).map((r) => r.permission);
  return g;
};

export function registerGrantRoutes(router, { db, secret }) {
  void secret;

  // POST /v1/orgs/:org/grants — grant:create. No laundering (D9): the caller
  // must hold every granted permission at the grant's scope, and never grant
  // to themselves.
  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    let createdId = null;
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'grant.create', targetType: 'grant', targetId: null },
      async () => {
        assertOrgLive(db, ctx.orgId);
        assertCan(db, ctx, 'grant:create', null);
        const { userId, deviceId = null, effect, permissions, startsAt, expiresAt } = ctx.body ?? {};
        if (userId === ctx.userId) throw forbidden('cannot grant permissions to yourself');
        if (!userId || typeof userId !== 'string') throw badRequest('userId is required');
        if (effect !== 'allow' && effect !== 'deny') throw badRequest("effect must be 'allow' or 'deny'");
        if (!Array.isArray(permissions) || permissions.length === 0) {
          throw badRequest('permissions must be a non-empty array');
        }

        const target = db
          .prepare("SELECT user_id FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'")
          .get(ctx.orgId, userId);
        if (!target) throw notFound('user not found');
        if (deviceId !== null) {
          const dev = db
            .prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL')
            .get(deviceId, ctx.orgId);
          if (!dev) throw notFound('device not found');
        }

        // Known patterns only (wildcards included): anything else is a 400
        // with reason unknown_permission — never a silent deny (D19). Checked
        // in code because the FK violation would otherwise surface as a 500.
        const known = new Set(db.prepare('SELECT pattern FROM permission_patterns').all().map((r) => r.pattern));
        for (const p of permissions) {
          if (typeof p !== 'string' || !known.has(p)) {
            throw new HttpError(400, 'VALIDATION', `unknown permission ${p}`, 'unknown_permission');
          }
        }

        const starts = normalizeTs(startsAt ?? null, 'startsAt');
        const expires = normalizeTs(expiresAt ?? null, 'expiresAt');
        if (starts && expires && expires <= starts) throw badRequest('expiresAt must be after startsAt');
        if (expires && expires <= nowIso()) {
          throw new HttpError(400, 'GRANT_EXPIRED', 'grant is already expired', 'expired_grant');
        }

        assertMayGrant(db, ctx, permissions, deviceId);

        const tx = db.transaction(() => {
          createdId = newId('grt');
          db.prepare(
            `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(createdId, ctx.orgId, userId, deviceId, effect, starts, expires, ctx.userId);
          const put = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
          for (const p of new Set(permissions)) put.run(createdId, p);
          bumpPermVersion(db, { orgId: ctx.orgId, userId });
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'grant.create',
            targetType: 'grant',
            targetId: createdId,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 201, grantShape(db, createdId));
  });

  // GET /v1/orgs/:org/grants — user:read, optionally ?userId= filtered.
  router.get('/v1/orgs/:org/grants', async (ctx, params, res) => {
    assertOrgLive(db, ctx.orgId);
    assertCan(db, ctx, 'user:read', null);
    const userId = ctx.query.get('userId');
    const rows = (userId
      ? db.prepare('SELECT id FROM grants WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL ORDER BY id').all(ctx.orgId, userId)
      : db.prepare('SELECT id FROM grants WHERE org_id = ? AND revoked_at IS NULL ORDER BY id').all(ctx.orgId)
    ).map((r) => grantShape(db, r.id));
    send(res, 200, { grants: rows });
  });

  // DELETE /v1/orgs/:org/grants/:id — grant:revoke. An already-revoked grant
  // is 404: it is no longer visible. Revocation bumps the target's version,
  // so the next request (not the running sessions) reflects the change.
  router.delete('/v1/orgs/:org/grants/:id', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'grant.revoke', targetType: 'grant', targetId: params.id },
      async () => {
        assertOrgLive(db, ctx.orgId);
        assertCan(db, ctx, 'grant:revoke', null);
        const tx = db.transaction(() => {
          const g = db
            .prepare('SELECT id, user_id AS userId FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL')
            .get(params.id, ctx.orgId);
          if (!g) throw notFound('grant not found');
          db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
          bumpPermVersion(db, { orgId: ctx.orgId, userId: g.userId });
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'grant.revoke',
            targetType: 'grant',
            targetId: params.id,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 200, { id: params.id, revoked: true });
  });
}

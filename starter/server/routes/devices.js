// Device routes: list (with per-row resolved sets), detail, provision,
// rename, decommission, transfer. Shapes follow BRIEF.md §5.1/§5.2.

import { send, badRequest, notFound, forbidden } from '../http.js';
import { assertCan, resolveDevices, resolve } from '../permissions.js';
import { endActiveSessions } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { nowIso, newId, bumpPermVersion } from '../db.js';

const DEVICE_KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

const assertOrgLive = (db, orgId) => {
  const row = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!row) throw notFound('org not found');
};

// Device scoped to THIS org: missing, soft-deleted, or living in another org
// all read identically as 404 (PERMISSIONS.md §5 — no cross-org oracle).
const targetDevice = (db, orgId, deviceId) => {
  const row = db
    .prepare('SELECT id, org_id AS orgId, name, kind, online FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL')
    .get(deviceId, orgId);
  if (!row) throw notFound('device not found');
  return { ...row, online: row.online === 1 };
};

const withPermissions = (db, ctx, device) => ({
  ...device,
  permissions: resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id }).permissions,
});

export function registerDeviceRoutes(router, { db, secret }) {
  void secret;

  // GET /v1/orgs/:org/devices — device:list gates the endpoint; device:view
  // gates ROW INCLUSION (denied rows are absent, never redacted). One shared
  // resolveDevices fetch for every row — never one query per row (§6).
  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    assertOrgLive(db, ctx.orgId);
    assertCan(db, ctx, 'device:list', null);
    const rows = db
      .prepare('SELECT id, name, kind, online FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name ASC')
      .all(ctx.orgId)
      .map((r) => ({ ...r, online: r.online === 1 }));
    const { byDevice } = resolveDevices(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceIds: rows.map((r) => r.id),
    });
    send(res, 200, {
      devices: rows
        .filter((r) => byDevice[r.id]['device:view'].effect === 'allow')
        .map((r) => ({ ...r, permissions: byDevice[r.id] })),
    });
  });

  // GET /v1/orgs/:org/devices/:id — device:view.
  router.get('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'device.view', targetType: 'device', targetId: params.id },
      async () => {
        assertOrgLive(db, ctx.orgId);
        targetDevice(db, ctx.orgId, params.id);
        assertCan(db, ctx, 'device:view', params.id);
      }
    );
    send(res, 200, withPermissions(db, ctx, targetDevice(db, ctx.orgId, params.id)));
  });

  // POST /v1/orgs/:org/devices — device:provision. kind is validated in code:
  // letting the CHECK fire would surface a raw SqliteError as a 500.
  router.post('/v1/orgs/:org/devices', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'device.provision', targetType: 'device', targetId: null },
      async () => {
        assertOrgLive(db, ctx.orgId);
        assertCan(db, ctx, 'device:provision', null);
        const { name, kind, online } = ctx.body ?? {};
        if (typeof name !== 'string' || name.trim().length === 0 || name.length > 200) {
          throw badRequest('name must be a non-empty string');
        }
        if (!DEVICE_KINDS.includes(kind)) throw badRequest(`kind must be one of ${DEVICE_KINDS.join(', ')}`);
        const id = newId('dev');
        const tx = db.transaction(() => {
          db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?, ?, ?, ?, ?)').run(
            id,
            ctx.orgId,
            name.trim(),
            kind,
            online === undefined ? 0 : online ? 1 : 0
          );
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'device.provision',
            targetType: 'device',
            targetId: id,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
        send(res, 201, withPermissions(db, ctx, targetDevice(db, ctx.orgId, id)));
      }
    );
  });

  // PATCH /v1/orgs/:org/devices/:id — device:update.
  router.patch('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'device.update', targetType: 'device', targetId: params.id },
      async () => {
        assertOrgLive(db, ctx.orgId);
        targetDevice(db, ctx.orgId, params.id);
        assertCan(db, ctx, 'device:update', params.id);
        const { name, online } = ctx.body ?? {};
        if (name === undefined && online === undefined) throw badRequest('nothing to update');
        if (name !== undefined && (typeof name !== 'string' || name.trim().length === 0 || name.length > 200)) {
          throw badRequest('name must be a non-empty string');
        }
        if (online !== undefined && typeof online !== 'boolean') throw badRequest('online must be a boolean');
        const tx = db.transaction(() => {
          if (name !== undefined) db.prepare('UPDATE devices SET name = ? WHERE id = ?').run(name.trim(), params.id);
          if (online !== undefined) db.prepare('UPDATE devices SET online = ? WHERE id = ?').run(online ? 1 : 0, params.id);
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'device.update',
            targetType: 'device',
            targetId: params.id,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 200, withPermissions(db, ctx, targetDevice(db, ctx.orgId, params.id)));
  });

  // DELETE /v1/orgs/:org/devices/:id — device:provision. Soft-delete (sessions
  // reference the row; history survives) and end live sessions as
  // device_transferred — a decommissioned device must not keep remote hands.
  router.delete('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'device.decommission', targetType: 'device', targetId: params.id },
      async () => {
        assertOrgLive(db, ctx.orgId);
        targetDevice(db, ctx.orgId, params.id);
        assertCan(db, ctx, 'device:provision', null);
        const tx = db.transaction(() => {
          db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), params.id);
          endActiveSessions(db, { deviceId: params.id, reason: 'device_transferred' });
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'device.decommission',
            targetType: 'device',
            targetId: params.id,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 200, { id: params.id, deleted: true });
  });

  // POST /v1/orgs/:org/devices/:id/transfer — device:provision in BOTH orgs.
  // Sessions on the device end (device_transferred); device-scoped grants die
  // with the move (they described authority in the source org — revoke, don't
  // delete, so the trail survives), org-wide grants never named the device and
  // stay. Every affected user gets a perm_version bump.
  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, params, res) => {
    let destOrgId = null;
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'device.transfer', targetType: 'device', targetId: params.id },
      async () => {
        assertOrgLive(db, ctx.orgId);
        targetDevice(db, ctx.orgId, params.id);
        assertCan(db, ctx, 'device:provision', null);
        const { toOrgId } = ctx.body ?? {};
        if (!toOrgId || typeof toOrgId !== 'string') throw badRequest('toOrgId is required');
        if (toOrgId === ctx.orgId) throw badRequest('device is already in this org');
        destOrgId = toOrgId;
        const dest = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(toOrgId);
        if (!dest) throw notFound('org not found');
        const destPerms = resolve(db, { userId: ctx.userId, orgId: toOrgId });
        if (destPerms.permissions['device:provision']?.effect !== 'allow') {
          throw forbidden('missing device:provision in destination org');
        }
        const tx = db.transaction(() => {
          db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(toOrgId, params.id);
          endActiveSessions(db, { deviceId: params.id, reason: 'device_transferred' });
          const affected = db
            .prepare('SELECT DISTINCT user_id AS userId FROM grants WHERE device_id = ? AND revoked_at IS NULL')
            .all(params.id);
          db.prepare('UPDATE grants SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL').run(
            nowIso(),
            params.id
          );
          for (const u of affected) bumpPermVersion(db, { orgId: ctx.orgId, userId: u.userId });
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'device.transfer',
            targetType: 'device',
            targetId: params.id,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 200, { id: params.id, orgId: destOrgId });
  });
}

// Organization routes: list, create, rename/retheme, remove.
// Shapes follow BRIEF.md §5.1; errors follow PERMISSIONS.md §5.

import { send, badRequest, notFound } from '../http.js';
import { assertCan } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { nowIso, newId } from '../db.js';
import { activeOrgs, orgEntries } from './auth.js';

// Default themes for orgs created without one. check-api creates orgs with
// only a name, and the console must tell orgs apart at a glance
// (data-org-theme), so the default cycles a fixed palette by live-org count —
// sequential creates always differ, deterministically.
const THEME_PALETTE = ['cobalt', 'amber', 'emerald', 'crimson', 'violet', 'teal', 'rose', 'slate'];

const defaultTheme = (db) => {
  const n = db.prepare('SELECT COUNT(*) AS n FROM organizations WHERE deleted_at IS NULL').get().n;
  return THEME_PALETTE[n % THEME_PALETTE.length];
};

// A token outlives its org's deletion (context checks membership, not the org
// row), so every :org handler re-establishes visibility first: deleted or
// missing orgs 404 here, before any permission check runs.
const assertOrgLive = (db, orgId) => {
  const row = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!row) throw notFound('org not found');
};

export function registerOrgRoutes(router, { db, secret }) {
  void secret;

  // GET /v1/orgs — authenticated. The caller's active orgs with per-org roles.
  router.get('/v1/orgs', async (ctx, params, res) => {
    send(res, 200, { orgs: orgEntries(activeOrgs(db, ctx.userId)) });
  });

  // POST /v1/orgs — authenticated. Anyone may create; the creator becomes the
  // sole owner (which is exactly what makes LAST_OWNER reachable on leave).
  router.post('/v1/orgs', async (ctx, params, res) => {
    const { name, theme } = ctx.body ?? {};
    if (typeof name !== 'string' || name.trim().length === 0) throw badRequest('name is required');
    if (name.trim().length > 200) throw badRequest('name is too long');
    if (theme !== undefined && (typeof theme !== 'string' || theme.trim().length === 0 || theme.length > 50)) {
      throw badRequest('theme must be a non-empty string');
    }

    const orgId = newId('org');
    const entry = db.transaction(() => {
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(
        orgId,
        name.trim(),
        theme?.trim() || defaultTheme(db)
      );
      db.prepare(
        "INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, 'owner', 'active', ?)"
      ).run(newId('mem'), orgId, ctx.userId, nowIso());
      audit(db, {
        orgId,
        actorId: ctx.userId,
        action: 'org.create',
        targetType: 'org',
        targetId: orgId,
        result: 'allow',
        reasonCode: null,
        requestId: ctx.requestId,
      });
      return db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(orgId);
    })();

    send(res, 201, { id: entry.id, name: entry.name, theme: entry.theme, role: 'owner' });
  });

  // PATCH /v1/orgs/:org — org:update. Rename and/or retheme.
  router.patch('/v1/orgs/:org', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'org.update', targetType: 'org', targetId: ctx.orgId },
      async () => {
        assertOrgLive(db, ctx.orgId);
        assertCan(db, ctx, 'org:update', null);
        const { name, theme } = ctx.body ?? {};
        if (name === undefined && theme === undefined) throw badRequest('nothing to update');
        if (name !== undefined && (typeof name !== 'string' || name.trim().length === 0 || name.length > 200)) {
          throw badRequest('name must be a non-empty string');
        }
        if (theme !== undefined && (typeof theme !== 'string' || theme.trim().length === 0 || theme.length > 50)) {
          throw badRequest('theme must be a non-empty string');
        }
        const tx = db.transaction(() => {
          if (name !== undefined) db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(name.trim(), ctx.orgId);
          if (theme !== undefined) db.prepare('UPDATE organizations SET theme = ? WHERE id = ?').run(theme.trim(), ctx.orgId);
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'org.update',
            targetType: 'org',
            targetId: ctx.orgId,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 200, db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(ctx.orgId));
  });

  // DELETE /v1/orgs/:org — org:delete. Soft-delete (deleted_at): the schema's
  // FKs forbid hard-deleting an org with members, and history must survive.
  // A deleted org vanishes from membership queries, so its tokens 401 after.
  router.delete('/v1/orgs/:org', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'org.delete', targetType: 'org', targetId: ctx.orgId },
      async () => {
        assertOrgLive(db, ctx.orgId);
        assertCan(db, ctx, 'org:delete', null);
        const tx = db.transaction(() => {
          db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), ctx.orgId);
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'org.delete',
            targetType: 'org',
            targetId: ctx.orgId,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 200, { id: ctx.orgId, deleted: true });
  });
}

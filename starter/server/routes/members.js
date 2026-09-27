// Member routes: list, role changes, suspend/reinstate, remove, leave, effective.
// Shapes follow BRIEF.md §5.1/§5.2; the people-ops table in AUTH-DATA-MODEL.md §7
// plus PERMISSIONS.md §6 govern who may do what. Gate order per route:
// visibility (org live, target in this org → 404) before permission (→ 403)
// before actor rules (self, rank, last owner).

import { send, badRequest, notFound, selfRoleChange } from '../http.js';
import { assertCan, resolve } from '../permissions.js';
import {
  assertRoleExists,
  assertCanModify,
  assertNotLastOwner,
  endActiveSessions,
} from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { bumpPermVersion } from '../db.js';

const assertOrgLive = (db, orgId) => {
  const row = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!row) throw notFound('org not found');
};

// Target membership scoped to THIS org: cross-org user ids 404 rather than
// leaking existence (or non-existence) across the org boundary.
const targetMembership = (db, orgId, userId) => {
  const row = db
    .prepare('SELECT user_id AS userId, role, status FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);
  if (!row) throw notFound('member not found');
  return row;
};

export function registerMemberRoutes(router, { db, secret }) {
  void secret;

  // GET /v1/orgs/:org/members — user:read.
  router.get('/v1/orgs/:org/members', async (ctx, params, res) => {
    assertOrgLive(db, ctx.orgId);
    assertCan(db, ctx, 'user:read', null);
    const rows = db
      .prepare(
        `SELECT m.user_id AS userId, u.email, u.name, m.role, m.status, m.joined_at AS joinedAt
           FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.org_id = ? ORDER BY u.email ASC`
      )
      .all(ctx.orgId);
    send(res, 200, { members: rows });
  });

  // PATCH /v1/orgs/:org/members/:userId — user:role:update. Rank checked
  // against BOTH the current and the new role (promoting viewer→admin needs
  // admin-beating authority too, not just authority over viewers). Self-change
  // is rejected before rank checks: the rule is about the actor, and checking
  // it first gives one stable code however the roles compare. Role changes
  // bump perm_version (old tokens go TOKEN_STALE) but never end sessions in
  // flight — grandfathering (PERMISSIONS.md §7).
  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'member.role.update', targetType: 'user', targetId: params.userId },
      async () => {
        assertOrgLive(db, ctx.orgId);
        const target = targetMembership(db, ctx.orgId, params.userId);
        assertCan(db, ctx, 'user:role:update', null);
        if (params.userId === ctx.userId) throw selfRoleChange();
        const { role } = ctx.body ?? {};
        assertRoleExists(db, role);
        assertCanModify(db, ctx.role, target.role);
        assertCanModify(db, ctx.role, role);
        const tx = db.transaction(() => {
          if (target.role === 'owner' && role !== 'owner') assertNotLastOwner(db, ctx.orgId, params.userId);
          db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(
            role,
            ctx.orgId,
            params.userId
          );
          bumpPermVersion(db, { orgId: ctx.orgId, userId: params.userId });
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'member.role.update',
            targetType: 'user',
            targetId: params.userId,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    send(res, 200, db.prepare('SELECT user_id AS userId, role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, params.userId));
  });

  // POST /v1/orgs/:org/members/:userId/suspend — user:remove + rank rules.
  // Suspended callers keep a valid token; resolve() empties their set, so gated
  // routes 403 from here on. Live sessions end NOW (user_suspended): tenancy
  // event, not a permission tweak. Idempotent: re-suspending returns the state.
  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'member.suspend', targetType: 'user', targetId: params.userId },
      async () => {
        assertOrgLive(db, ctx.orgId);
        const target = targetMembership(db, ctx.orgId, params.userId);
        assertCan(db, ctx, 'user:remove', null);
        assertCanModify(db, ctx.role, target.role);
        if (target.status === 'active') {
          const tx = db.transaction(() => {
            db.prepare("UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?").run(
              ctx.orgId,
              params.userId
            );
            bumpPermVersion(db, { orgId: ctx.orgId, userId: params.userId });
            endActiveSessions(db, { orgId: ctx.orgId, userId: params.userId, reason: 'user_suspended' });
            audit(db, {
              orgId: ctx.orgId,
              actorId: ctx.userId,
              action: 'member.suspend',
              targetType: 'user',
              targetId: params.userId,
              result: 'allow',
              reasonCode: null,
              requestId: ctx.requestId,
            });
          });
          tx();
        }
      }
    );
    send(res, 200, db.prepare('SELECT user_id AS userId, role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, params.userId));
  });

  // DELETE /v1/orgs/:org/members/:userId/suspend — user:remove. Reinstate to
  // active. The bump keeps pre-suspension tokens stale (suspension must
  // invalidate); ended sessions stay ended — reinstatement never revives them.
  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'member.reinstate', targetType: 'user', targetId: params.userId },
      async () => {
        assertOrgLive(db, ctx.orgId);
        const target = targetMembership(db, ctx.orgId, params.userId);
        assertCan(db, ctx, 'user:remove', null);
        assertCanModify(db, ctx.role, target.role);
        if (target.status === 'suspended') {
          const tx = db.transaction(() => {
            db.prepare("UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?").run(
              ctx.orgId,
              params.userId
            );
            bumpPermVersion(db, { orgId: ctx.orgId, userId: params.userId });
            audit(db, {
              orgId: ctx.orgId,
              actorId: ctx.userId,
              action: 'member.reinstate',
              targetType: 'user',
              targetId: params.userId,
              result: 'allow',
              reasonCode: null,
              requestId: ctx.requestId,
            });
          });
          tx();
        }
      }
    );
    send(res, 200, db.prepare('SELECT user_id AS userId, role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, params.userId));
  });

  // DELETE /v1/orgs/:org/members/:userId — user:remove + rank + last-owner.
  // Users are never deleted (D15): removal flips membership to removed, ends
  // their sessions here (membership_removed), and leaves other orgs alone.
  const removeMember = async (ctx, userId, action) => {
    assertOrgLive(db, ctx.orgId);
    const target = targetMembership(db, ctx.orgId, userId);
    // Leaving is self-service: the table lists no permission for it, and rank
    // is about authority over OTHERS — an admin walking away needs no rank
    // over themselves. Last-owner still applies (ownerless orgs are forbidden
    // however the last owner departs).
    if (userId !== ctx.userId) {
      assertCan(db, ctx, 'user:remove', null);
      assertCanModify(db, ctx.role, target.role);
    }
    if (target.status !== 'removed') {
      const tx = db.transaction(() => {
        if (target.role === 'owner') assertNotLastOwner(db, ctx.orgId, userId);
        db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, userId);
        bumpPermVersion(db, { orgId: ctx.orgId, userId });
        endActiveSessions(db, { orgId: ctx.orgId, userId, reason: 'membership_removed' });
        audit(db, {
          orgId: ctx.orgId,
          actorId: ctx.userId,
          action,
          targetType: 'user',
          targetId: userId,
          result: 'allow',
          reasonCode: null,
          requestId: ctx.requestId,
        });
      });
      tx();
    }
  };

  // DELETE /v1/orgs/:org/members/me — self-leave. No permission needed beyond
  // selfhood, but the last owner may not walk away from an ownerless org.
  // NOTE: the literal MUST register before '/members/:userId' below — same
  // segment count, first match wins, and 'me' would otherwise bind :userId.
  router.delete('/v1/orgs/:org/members/me', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'member.leave', targetType: 'user', targetId: ctx.userId },
      async () => removeMember(ctx, ctx.userId, 'member.leave')
    );
    send(res, 200, { userId: ctx.userId, orgId: ctx.orgId, status: 'removed' });
  });

  router.delete('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'member.remove', targetType: 'user', targetId: params.userId },
      async () => removeMember(ctx, params.userId, 'member.remove')
    );
    send(res, 200, db.prepare('SELECT user_id AS userId, role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, params.userId));
  });

  // GET /v1/orgs/:org/users/:userId/effective — user:read, or self. The
  // resolver's answer verbatim: { role, permissions }.
  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, params, res) => {
    assertOrgLive(db, ctx.orgId);
    targetMembership(db, ctx.orgId, params.userId);
    if (params.userId !== ctx.userId) assertCan(db, ctx, 'user:read', null);
    const { role, permissions } = resolve(db, { userId: params.userId, orgId: ctx.orgId });
    send(res, 200, { role, permissions });
  });
}

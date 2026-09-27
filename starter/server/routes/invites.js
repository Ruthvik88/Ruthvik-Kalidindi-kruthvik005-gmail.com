// Invite routes: create/list/cancel (member-gated) + public peek/accept.
// Liveness lives in exactly one place — the invites row. No placeholder
// memberships are written at create time (that would dual-track liveness);
// accept handles every prior membership state explicitly instead.

import { send, badRequest, notFound, gone, conflict } from '../http.js';
import { assertCan } from '../permissions.js';
import { assertRoleExists, assertCanModify } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { nowIso, newId } from '../db.js';
import { issueAccessToken, hashPassword, newInviteToken, hashInviteToken } from '../auth.js';
import { mintRefresh, cookieHeader } from './auth.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const assertOrgLive = (db, orgId) => {
  const row = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!row) throw notFound('org not found');
};

const normEmail = (email) => String(email ?? '').trim().toLowerCase();
const validEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Derived status: the row carries timestamps, not a state column.
const inviteStatus = (inv, now) => {
  if (inv.accepted_at !== null) return 'accepted';
  if (inv.revoked_at !== null) return 'revoked';
  if (inv.expires_at <= now) return 'expired';
  return 'pending';
};

const inviteShape = (db, row, now) => ({
  id: row.id,
  email: row.email,
  role: row.role,
  status: inviteStatus(row, now),
  expiresAt: row.expires_at,
  createdAt: row.created_at,
});

export function registerInviteRoutes(router, { db, secret }) {
  // POST /v1/orgs/:org/invites — user:invite. The raw token is returned once,
  // hashed at rest, never logged.
  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    let createdId = null;
    let rawToken = null;
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'invite.create', targetType: 'invite', targetId: null },
      async () => {
        assertOrgLive(db, ctx.orgId);
        assertCan(db, ctx, 'user:invite', null);
        const { email, role } = ctx.body ?? {};
        const clean = normEmail(email);
        if (!validEmail(clean)) throw badRequest('email is not valid');
        assertRoleExists(db, role);
        assertCanModify(db, ctx.role, role);
        const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(clean);
        if (existing) {
          const mem = db
            .prepare("SELECT status FROM memberships WHERE org_id = ? AND user_id = ?")
            .get(ctx.orgId, existing.id);
          if (mem && mem.status === 'active') throw conflict('user is already a member');
        }
        const live = db
          .prepare(
            `SELECT id FROM invites WHERE org_id = ? AND email = ?
               AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?`
          )
          .get(ctx.orgId, clean, nowIso());
        if (live) throw conflict('invite already pending');
        const tx = db.transaction(() => {
          createdId = newId('inv');
          rawToken = newInviteToken();
          try {
            db.prepare(
              `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)`
            ).run(
              createdId,
              ctx.orgId,
              clean,
              role,
              hashInviteToken(rawToken),
              ctx.userId,
              new Date(Date.now() + INVITE_TTL_MS).toISOString()
            );
          } catch (err) {
            // Concurrent double-invite: the partial unique index decides the
            // winner instead of application code (no check-then-act race).
            if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE') throw conflict('invite already pending');
            throw err;
          }
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'invite.create',
            targetType: 'invite',
            targetId: createdId,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });
        tx();
      }
    );
    const row = db.prepare('SELECT * FROM invites WHERE id = ?').get(createdId);
    send(res, 201, { ...inviteShape(db, row, nowIso()), inviteToken: rawToken });
  });

  // GET /v1/orgs/:org/invites — user:invite. Hashes never leave the server.
  router.get('/v1/orgs/:org/invites', async (ctx, params, res) => {
    assertOrgLive(db, ctx.orgId);
    assertCan(db, ctx, 'user:invite', null);
    const now = nowIso();
    const rows = db
      .prepare('SELECT * FROM invites WHERE org_id = ? ORDER BY created_at DESC, id DESC')
      .all(ctx.orgId)
      .map((r) => inviteShape(db, r, now));
    send(res, 200, { invites: rows });
  });

  // DELETE /v1/orgs/:org/invites/:id — user:invite. Cancelling sets revoked_at;
  // consumed or already-dead invites 404 like revoked grants do.
  router.delete('/v1/orgs/:org/invites/:id', async (ctx, params, res) => {
    await auditDenials(
      db,
      ctx,
      { orgId: ctx.orgId, action: 'invite.cancel', targetType: 'invite', targetId: params.id },
      async () => {
        assertOrgLive(db, ctx.orgId);
        assertCan(db, ctx, 'user:invite', null);
        const tx = db.transaction(() => {
          const inv = db
            .prepare('SELECT * FROM invites WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL')
            .get(params.id, ctx.orgId);
          if (!inv) throw notFound('invite not found');
          db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'invite.cancel',
            targetType: 'invite',
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

  // GET /v1/invites/:token — PUBLIC. Exactly enough to render the accept page
  // ("invited to Acme Robotics as operator"): org name, role, email, expiry.
  // No ids, no counts, no member or device data — the holder is not a member.
  // Anything not live reads as GONE (peek asks "is there a live invite?").
  const findLiveInvite = (db, raw) => {
    const inv = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(hashInviteToken(raw));
    if (!inv) throw notFound('invite not found');
    if (inviteStatus(inv, nowIso()) !== 'pending') throw gone('invite is no longer valid');
    return inv;
  };

  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const inv = findLiveInvite(db, params.token);
    const org = db.prepare('SELECT name FROM organizations WHERE id = ?').get(inv.org_id);
    send(res, 200, { orgName: org?.name ?? null, role: inv.role, email: inv.email, expiresAt: inv.expires_at });
  });

  // POST /v1/invites/:token/accept — PUBLIC. One transaction: claim the token
  // (exactly one concurrent accept wins via the conditional UPDATE), attach or
  // create the user, activate the membership, issue tokens. The raw token is
  // the credential, so no password is asked of an existing user; a new user
  // must supply name and password (users.name/password_hash are NOT NULL).
  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    const inv = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(hashInviteToken(params.token));
    if (!inv) throw notFound('invite not found');
    const now = nowIso();
    if (inv.revoked_at !== null || inv.expires_at <= now) throw gone('invite is no longer valid');
    if (inv.accepted_at !== null) throw conflict('invite already accepted');

    const { name, password } = ctx.body ?? {};
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(inv.email);
    if (!user && (!name || !password)) throw badRequest('name and password are required for a new account');

    let userId;
    let access;
    const tx = db.transaction(() => {
      const claimed = db
        .prepare('UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ? AND accepted_at IS NULL')
        .run(now, user?.id ?? null, inv.id);
      if (claimed.changes === 0) throw conflict('invite already accepted');

      if (!user) {
        userId = newId('usr');
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)').run(
          userId,
          inv.email,
          String(name),
          hashPassword(String(password))
        );
      } else {
        userId = user.id;
      }

      const mem = db.prepare('SELECT status FROM memberships WHERE org_id = ? AND user_id = ?').get(inv.org_id, userId);
      if (!mem) {
        db.prepare(
          "INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, ?, 'active', ?)"
        ).run(newId('mem'), inv.org_id, userId, inv.role, now);
      } else if (mem.status === 'active') {
        throw conflict('user is already a member');
      } else {
        db.prepare('UPDATE memberships SET role = ?, status = ? WHERE org_id = ? AND user_id = ?').run(
          inv.role,
          'active',
          inv.org_id,
          userId
        );
      }
      db.prepare('UPDATE invites SET accepted_by = ? WHERE id = ?').run(userId, inv.id);

      const perm = db
        .prepare('SELECT perm_version AS permVersion FROM memberships WHERE org_id = ? AND user_id = ?')
        .get(inv.org_id, userId);
      access = issueAccessToken(
        { userId, orgId: inv.org_id, role: inv.role, permVersion: perm.permVersion },
        secret
      );
      const { raw } = mintRefresh(db, userId);
      res.setHeader('Set-Cookie', cookieHeader(raw));
      audit(db, {
        orgId: inv.org_id,
        actorId: userId,
        action: 'invite.accept',
        targetType: 'invite',
        targetId: inv.id,
        result: 'allow',
        reasonCode: null,
        requestId: ctx.requestId,
      });
    });
    tx();
    send(res, 200, { token: access, role: inv.role, userId, orgId: inv.org_id });
  });
}

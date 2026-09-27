// Auth routes: login, refresh rotation, org switch, self.
// Response shapes follow BRIEF.md §5.1; error shapes follow PERMISSIONS.md §5.

import { send, badRequest, unauthenticated } from '../http.js';
import {
  issueAccessToken,
  verifyPassword,
  newRefreshToken,
  hashRefreshToken,
  REFRESH_TTL_SECONDS,
} from '../auth.js';
import { resolve } from '../permissions.js';
import { nowIso, newId } from '../db.js';

const COOKIE = 'refresh_token';

// The refresh cookie must actually be sent back on plain-http localhost (dev,
// check-api, Playwright all run http), where browsers drop `Secure` cookies —
// so HttpOnly + Path + Max-Age + SameSite=Strict, and NO Secure flag. Logged
// in DECISIONS.md: working rotation beats attribute literalism here.
const cookieHeader = (raw) =>
  `${COOKIE}=${raw}; HttpOnly; Path=/; Max-Age=${REFRESH_TTL_SECONDS}; SameSite=Strict`;
const clearCookieHeader = () => `${COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict`;

const readCookie = (req) => {
  const header = String(req.headers?.cookie ?? '');
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
};

// Active memberships with org + rank, best authority first. Rank orders the
// DEFAULT org only — it never answers a permission question (D8).
export const activeOrgs = (db, userId) =>
  db
    .prepare(
      `SELECT m.org_id AS orgId, m.role, m.perm_version AS permVersion,
              o.name, o.theme, r.rank AS rank
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
         JOIN roles r ON r.key = m.role
        WHERE m.user_id = ? AND m.status = 'active'
        ORDER BY r.rank DESC, o.name ASC`
    )
    .all(userId);

export const orgEntries = (rows) => rows.map((r) => ({ id: r.orgId, name: r.name, theme: r.theme, role: r.role }));

const mintRefresh = (db, userId, familyId = newId('fam')) => {
  const raw = newRefreshToken();
  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run(
    newId('rt'),
    userId,
    hashRefreshToken(raw),
    familyId,
    new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString()
  );
  return { raw, familyId };
};

// Refresh tokens carry no org (the schema has no org_id on refresh_tokens by
// design — D12 keeps them a single global credential). So a refresh mints for
// the default org, exactly like a fresh login.
const defaultAccess = (db, secret, userId) => {
  const orgs = activeOrgs(db, userId);
  if (orgs.length === 0) throw unauthenticated('not a member of this org');
  const picked = orgs[0];
  return {
    picked,
    orgs,
    token: issueAccessToken(
      { userId, orgId: picked.orgId, role: picked.role, permVersion: picked.permVersion },
      secret
    ),
  };
};

export function registerAuthRoutes(router, { db, secret }) {
  // POST /v1/auth/login — public. Wrong password and unknown email read
  // identically (BRIEF.md §5.3): no account-enumeration oracle.
  router.post('/v1/auth/login', async (ctx, params, res) => {
    const { email, password, orgId } = ctx.body ?? {};
    if (!email || !password) throw badRequest('email and password are required');
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).trim().toLowerCase());
    if (!user || !verifyPassword(String(password), user.password_hash)) {
      throw unauthenticated('invalid email or password');
    }

    const orgs = activeOrgs(db, user.id);
    if (orgs.length === 0) throw unauthenticated('invalid email or password');
    const picked = orgId ? orgs.find((o) => o.orgId === orgId) : orgs[0];
    if (!picked) throw unauthenticated('not a member of this org');

    const { raw } = mintRefresh(db, user.id);
    res.setHeader('Set-Cookie', cookieHeader(raw));
    send(res, 200, {
      token: issueAccessToken(
        { userId: user.id, orgId: picked.orgId, role: picked.role, permVersion: picked.permVersion },
        secret
      ),
      role: picked.role,
      orgId: picked.orgId,
      orgs: orgEntries(orgs),
    });
  });

  // POST /v1/auth/refresh — public (the cookie IS the credential). Rotates:
  // the presented token dies, a same-family successor is set. Presenting an
  // already-rotated token is replay → the whole family dies (AUTH-DATA-MODEL
  // §2), because the token escaped somewhere it shouldn't have.
  router.post('/v1/auth/refresh', async (ctx, params, res) => {
    const raw = readCookie(ctx.req);
    if (!raw) throw unauthenticated('missing refresh token');
    const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (!row) throw unauthenticated('invalid refresh token');
    if (row.revoked_at !== null) {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(nowIso(), row.family_id);
      res.setHeader('Set-Cookie', clearCookieHeader());
      throw unauthenticated('refresh token reuse detected');
    }
    if (row.expires_at <= nowIso()) throw unauthenticated('refresh token expired');

    db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(nowIso(), row.id);
    const next = mintRefresh(db, row.user_id, row.family_id);
    const { picked, token } = defaultAccess(db, secret, row.user_id);
    res.setHeader('Set-Cookie', cookieHeader(next.raw));
    send(res, 200, { token, role: picked.role, orgId: picked.orgId });
  });

  // POST /v1/auth/token — authenticated. Mint an access token scoped to
  // another org the caller actively belongs to (D18: one org per token).
  // No org-existence check first: unknown org and non-member org both 401, so
  // the endpoint never tells a caller which org ids exist.
  router.post('/v1/auth/token', async (ctx, params, res) => {
    const { orgId } = ctx.body ?? {};
    if (!orgId) throw badRequest('orgId is required');
    const membership = db
      .prepare(
        `SELECT m.role, m.perm_version AS permVersion FROM memberships m
           JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
          WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active'`
      )
      .get(ctx.userId, orgId);
    if (!membership) throw unauthenticated('not a member of this org');
    send(res, 200, {
      token: issueAccessToken(
        { userId: ctx.userId, orgId, role: membership.role, permVersion: membership.permVersion },
        secret
      ),
      role: membership.role,
      orgId,
    });
  });

  // GET /v1/auth/me — authenticated. Identity + active org + per-org roles +
  // the org-level RESOLVED set (from the engine, never recomputed here).
  router.get('/v1/auth/me', async (ctx, params, res) => {
    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(ctx.userId);
    const org = db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(ctx.orgId);
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId });
    send(res, 200, {
      user,
      org,
      role: ctx.role,
      orgs: orgEntries(activeOrgs(db, ctx.userId)),
      permissions,
    });
  });
}

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

// Prepared once at module scope, not per request: index.js calls
// authenticate(db, SECRET) on EVERY request, so a prepare() inside it would
// recompile the same SQL each time. This caches the compiled statement only,
// never results, so it cannot serve stale authority.
let findMembership = null;

export function authenticate(db, secret) {
  findMembership ??= db.prepare(
    'SELECT id, org_id, user_id, role, status, perm_version FROM memberships WHERE org_id = ? AND user_id = ?'
  );

  return function buildContext(req, params) {
    // 1. Bearer token off the header. Absent/malformed never reaches the verifier.
    const header = String(req.headers?.authorization ?? '').trim();
    const match = /^Bearer\s+(.+)$/i.exec(header);
    if (!match) throw unauthenticated('missing or malformed authorization header');

    // 2. Verify. Throws 401 UNAUTHENTICATED-shaped HttpError itself (Phase 1).
    const claims = verifyAccessToken(match[1], secret);

    // 3. Structural org isolation, before any DB work: the token's org is the
    // only org the caller may address. A different org is invisible (404, never
    // 403), and checking first means no membership oracle leaks through a
    // cross-org request. Routes without an :org param skip this entirely.
    // Convention (fixed Phase 3): org-scoped routes use :org, so params.org.
    if (params?.org !== undefined && params.org !== claims.org) throw notFound('org not found');

    // 4. Membership is the source of truth, not the token.
    const membership = findMembership.get(claims.org, claims.sub);
    if (!membership || membership.status === 'removed' || membership.status === 'invited') {
      throw unauthenticated('not a member of this org');
    }
    // Suspended passes through with a well-formed caller: resolve() denies
    // everything with reason 'suspended', so gated routes 403 with an empty
    // permission set (AUTH-DATA-MODEL.md §10).

    // 5. Freshness: a role/grant change takes effect on the NEXT request.
    assertFresh(claims, membership); // throws 401 TOKEN_STALE on pv mismatch

    // 6. Caller object. Role comes from the membership row, not the claims.
    return { userId: claims.sub, orgId: claims.org, role: membership.role, membership, claims };
  };
}

// Audit read endpoint. Pagination is defined, not clamped: out-of-range
// values are 400s, never silently narrowed.

import { send, badRequest, notFound } from '../http.js';
import { assertCan } from '../permissions.js';

// No contract pins these numbers beyond the tested boundaries (limit=1 and
// limit=200 pass; limit=0/-1/99999 and offset=-1 fail; huge offset is an empty
// 200). Default 100, max 1000 — documented here, not derived.
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;

const assertOrgLive = (db, orgId) => {
  const row = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!row) throw notFound('org not found');
};

const intParam = (value, name, { min, max }) => {
  if (value === null) return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) throw badRequest(`${name} must be an integer ${min}..${max}`);
  return n;
};

export function registerAuditRoutes(router, { db, secret }) {
  void secret;

  // GET /v1/orgs/:org/audit — audit:read. Newest first; rows mirror the table
  // (snake_case), denials included — that is the point of the log.
  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    assertOrgLive(db, ctx.orgId);
    assertCan(db, ctx, 'audit:read', null);
    const limit = intParam(ctx.query.get('limit') ?? String(DEFAULT_LIMIT), 'limit', { min: 1, max: MAX_LIMIT });
    const offset = intParam(ctx.query.get('offset') ?? '0', 'offset', { min: 0, max: Number.MAX_SAFE_INTEGER });
    const events = db
      .prepare(
        `SELECT id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at
           FROM audit_events WHERE org_id = ? ORDER BY at DESC, rowid DESC LIMIT ? OFFSET ?`
      )
      .all(ctx.orgId, limit, offset);
    send(res, 200, { events });
  });
}

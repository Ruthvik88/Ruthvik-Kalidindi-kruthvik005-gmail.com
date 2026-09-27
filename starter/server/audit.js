// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module only ever
// INSERTs. Two things the spec is explicit about (BRIEF.md §4, PERMISSIONS.md §8):
//
//   - DENIED attempts are recorded, not just successes. A log that only holds
//     successes cannot answer "who tried to change what".
//   - a single action produces a single row. Write the success row inside the same
//     transaction as the change it describes; do not also log the allow from a wrapper.
//
// Schema columns: id, org_id (NOT NULL), actor_id, action, target_type, target_id,
// result ('allow'|'deny'), reason_code, request_id, at.

import { HttpError } from './http.js';
import { newId } from './db.js';

// One row, one action. `at` is left to the schema default (strftime UTC) — the
// signature carries no timestamp, and inventing one would add a field the
// contract does not define. Call inside the same transaction as the mutation.
export function audit(db, { orgId, actorId, action, targetType, targetId, result, reasonCode, requestId }) {
  db.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    newId('aud'),
    orgId,
    actorId ?? null,
    action,
    targetType ?? null,
    targetId ?? null,
    result,
    reasonCode ?? null,
    requestId ?? null
  );
}

// Run fn(); if it refuses with a permission error (403), record the denial
// before rethrowing. Anything else — 404s, validation, stale tokens — passes
// through unlogged: a 404 is invisibility, not a denial, and logging it would
// write existence-oracle rows into a log that audit:read holders can read.
export async function auditDenials(db, ctx, meta, fn) {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      audit(db, {
        orgId: meta.orgId ?? ctx.orgId,
        actorId: ctx.userId ?? null,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? err.code,
        requestId: ctx.requestId ?? null,
      });
    }
    throw err;
  }
}

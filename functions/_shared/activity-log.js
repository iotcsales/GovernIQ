// functions/_shared/activity-log.js
//
// Shared activity_log helper for the three new office-record types
// (projects, documents, commitments). Grievance actions keep writing to
// grievance_audit exactly as before — this is a separate table, so the
// existing per-case audit trail is untouched. The My Day "What Changed"
// feed (functions/api/activity.js) merges both at read time.

export async function recordActivity(env, { entityType, entityId, action, detail, actorEmail, actorRole }) {
  await env.DB.prepare(
    `INSERT INTO activity_log (id, entity_type, entity_id, action, detail, actor_email, actor_role) VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), entityType, entityId, action, detail || null, actorEmail, actorRole).run();
}

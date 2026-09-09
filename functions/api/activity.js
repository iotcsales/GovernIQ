// functions/api/activity.js
//
// Merges grievance_audit (existing, per-case audit trail) with
// activity_log (new, for projects/documents/commitments) into one
// recent-activity feed for My Day's "What Changed" panel. Read-only —
// nothing writes here.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission } from "../_shared/permissions.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  if (!hasPermission(auth.user.role, "VIEW")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const limit = 12;

  const [grievanceActivity, otherActivity] = await Promise.all([
    env.DB.prepare(
      `SELECT ga.action, ga.detail, ga.actor_email, ga.actor_role, ga.created_at,
              'GRIEVANCE' as entity_type, g.id as entity_id, g.title as entity_title
       FROM grievance_audit ga JOIN grievances g ON g.id = ga.grievance_id
       ORDER BY ga.created_at DESC LIMIT ?`
    ).bind(limit).all(),
    env.DB.prepare(
      `SELECT action, detail, actor_email, actor_role, created_at, entity_type, entity_id, detail as entity_title
       FROM activity_log ORDER BY created_at DESC LIMIT ?`
    ).bind(limit).all(),
  ]);

  const merged = [...grievanceActivity.results, ...otherActivity.results]
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
    .slice(0, limit);

  return Response.json(merged);
}

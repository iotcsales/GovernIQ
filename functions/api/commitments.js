// functions/api/commitments.js
//
// Standalone follow-up commitments — things promised to a department or a
// citizen that aren't tied to a specific grievance's task list (e.g.
// "follow up with Health Dept on PHC staffing"). Can optionally reference
// a grievance via related_grievance_id, but doesn't require one.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission, canManageOfficeRecords } from "../_shared/permissions.js";
import { recordActivity } from "../_shared/activity-log.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  if (!hasPermission(auth.user.role, "VIEW")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const { results } = await env.DB.prepare(
    "SELECT * FROM commitments ORDER BY due_date ASC"
  ).all();
  return Response.json(results);
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  const { role, email } = auth.user;
  if (!canManageOfficeRecords(role)) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const body = await request.json();
  const title = (body.title || "").trim();
  if (!title) {
    return Response.json({ error: "VALIDATION_ERROR", message: "title is required" }, { status: 400 });
  }
  const id = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO commitments (id, title, description, due_date, status, related_grievance_id, created_by)
     VALUES (?, ?, ?, ?, 'IN_PROGRESS', ?, ?)`
  ).bind(id, title, body.description || null, body.dueDate || null, body.relatedGrievanceId || null, email).run();

  await recordActivity(env, {
    entityType: "COMMITMENT", entityId: id, action: "CREATED", detail: title,
    actorEmail: email, actorRole: role,
  });

  return Response.json({ id });
}

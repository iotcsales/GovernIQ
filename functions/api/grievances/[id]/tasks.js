// functions/api/grievances/[id]/tasks.js
//
// Tasks for a single grievance, persisted to D1 — previously these lived
// only in browser memory and vanished on refresh or in another session.

import { getVerifiedUser } from "../../../_shared/get-verified-user.js";
import { hasPermission, PERMISSIONS } from "../../../_shared/permissions.js";
import { loadGrievance, loadGrievanceWithAudit, recordAudit } from "../../../_shared/grievance-data.js";

async function checkAccess(request, env, id) {
  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return { error: Response.json({ error: auth.error }, { status: auth.status }) };
  const { role, email } = auth.user;

  const row = await loadGrievance(env, id);
  if (!row) return { error: Response.json({ error: "NOT_FOUND" }, { status: 404 }) };

  const scope = (PERMISSIONS[role] || {}).scope;
  if (scope === "OWN_ASSIGNED" && row.assigned_to !== email) {
    return { error: Response.json({ error: "FORBIDDEN" }, { status: 403 }) };
  }
  if (!hasPermission(role, "EDIT")) {
    return { error: Response.json({ error: "FORBIDDEN" }, { status: 403 }) };
  }
  return { role, email, row };
}

export async function onRequestPost(context) {
  const { request, env, params } = context;
  const id = params.id;

  const access = await checkAccess(request, env, id);
  if (access.error) return access.error;
  const { role, email } = access;

  const body = await request.json();
  const title = (body.title || "").trim();
  if (!title) return Response.json({ error: "VALIDATION_ERROR", message: "title is required" }, { status: 400 });
  const dueDate = body.dueDate || null;

  await env.DB.prepare(
    `INSERT INTO grievance_tasks (id, grievance_id, title, due_date, status, created_by) VALUES (?, ?, ?, ?, 'OPEN', ?)`
  ).bind(crypto.randomUUID(), id, title, dueDate, email).run();

  await recordAudit(env, { grievanceId: id, action: "TASK_CREATED", detail: title, actorEmail: email, actorRole: role });

  const result = await loadGrievanceWithAudit(env, id, hasPermission(role, "SENSITIVE_DATA_ACCESS"));
  return Response.json(result);
}

export async function onRequestPatch(context) {
  const { request, env, params } = context;
  const id = params.id;

  const access = await checkAccess(request, env, id);
  if (access.error) return access.error;
  const { role, email } = access;

  const body = await request.json();
  const { taskId, action } = body;
  if (action !== "COMPLETE") {
    return Response.json({ error: "UNKNOWN_ACTION" }, { status: 400 });
  }

  const task = await env.DB.prepare("SELECT id, title, grievance_id FROM grievance_tasks WHERE id = ? AND grievance_id = ?").bind(taskId, id).first();
  if (!task) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  await env.DB.prepare(
    `UPDATE grievance_tasks SET status='COMPLETED', completed_at=datetime('now') WHERE id=?`
  ).bind(taskId).run();

  await recordAudit(env, { grievanceId: id, action: "TASK_COMPLETED", detail: task.title, actorEmail: email, actorRole: role });

  const result = await loadGrievanceWithAudit(env, id, hasPermission(role, "SENSITIVE_DATA_ACCESS"));
  return Response.json(result);
}

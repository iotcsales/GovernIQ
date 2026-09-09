// functions/api/projects/[id].js
//
// Status updates for a single project (PLANNED -> IN_PROGRESS -> AT_RISK /
// DELAYED -> COMPLETED). Same permission gate as creating a project —
// running project status is an office-management action, not something
// every role that can view grievances should be able to change.

import { getVerifiedUser } from "../../_shared/get-verified-user.js";
import { canManageOfficeRecords } from "../../_shared/permissions.js";
import { recordActivity } from "../../_shared/activity-log.js";

const VALID_STATUSES = ["PLANNED", "IN_PROGRESS", "AT_RISK", "DELAYED", "COMPLETED"];

export async function onRequestPatch(context) {
  const { request, env, params } = context;
  const id = params.id;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  const { role, email } = auth.user;
  if (!canManageOfficeRecords(role)) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const row = await env.DB.prepare("SELECT * FROM projects WHERE id = ?").bind(id).first();
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const body = await request.json();
  const newStatus = body.status;
  if (!VALID_STATUSES.includes(newStatus)) {
    return Response.json({ error: "VALIDATION_ERROR", message: "Invalid status" }, { status: 400 });
  }

  await env.DB.prepare(
    `UPDATE projects SET status=?, updated_at=datetime('now') WHERE id=?`
  ).bind(newStatus, id).run();

  await recordActivity(env, {
    entityType: "PROJECT", entityId: id, action: "STATUS_CHANGED",
    detail: `${row.status.replace(/_/g, " ")} → ${newStatus.replace(/_/g, " ")}`,
    actorEmail: email, actorRole: role,
  });

  const updated = await env.DB.prepare("SELECT * FROM projects WHERE id = ?").bind(id).first();
  return Response.json(updated);
}

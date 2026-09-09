// functions/api/projects/[id].js
//
// Single-project detail (with its audit trail) plus the two write actions:
// EDIT (title/description/department/location/sanctioned date) and
// STATUS_CHANGE (PLANNED -> IN_PROGRESS -> AT_RISK/DELAYED -> COMPLETED).
// Same permission gate as creating a project — this is office-management
// data, not something every role that can view grievances should be able
// to change.

import { getVerifiedUser } from "../../_shared/get-verified-user.js";
import { hasPermission, canManageOfficeRecords } from "../../_shared/permissions.js";
import { recordActivity, loadActivityForEntity } from "../../_shared/activity-log.js";

const VALID_STATUSES = ["PLANNED", "IN_PROGRESS", "AT_RISK", "DELAYED", "COMPLETED"];

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const id = params.id;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  if (!hasPermission(auth.user.role, "VIEW")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const row = await env.DB.prepare("SELECT * FROM projects WHERE id = ?").bind(id).first();
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const audit = await loadActivityForEntity(env, "PROJECT", id);
  return Response.json({ ...row, audit });
}

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

  if (body.action === "EDIT") {
    const title = (body.title || "").trim();
    if (!title) {
      return Response.json({ error: "VALIDATION_ERROR", message: "title is required" }, { status: 400 });
    }
    await env.DB.prepare(
      `UPDATE projects SET title=?, description=?, department=?, location_text=?, sanctioned_date=?, updated_at=datetime('now') WHERE id=?`
    ).bind(
      title, body.description || null, body.department || null,
      body.locationText || null, body.sanctionedDate || null, id
    ).run();
    await recordActivity(env, { entityType: "PROJECT", entityId: id, action: "EDITED", detail: title, actorEmail: email, actorRole: role });

  } else if (body.action === "STATUS_CHANGE" || body.status) {
    // body.status kept as a fallback so this doesn't silently break if
    // something still calls the old pre-action shape.
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

  } else {
    return Response.json({ error: "UNKNOWN_ACTION" }, { status: 400 });
  }

  const updated = await env.DB.prepare("SELECT * FROM projects WHERE id = ?").bind(id).first();
  const audit = await loadActivityForEntity(env, "PROJECT", id);
  return Response.json({ ...updated, audit });
}

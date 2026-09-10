// functions/api/commitments/[id].js
//
// Single-commitment detail (with its audit trail) plus two write actions:
// EDIT (title/description/due date/linked grievance) and COMPLETE. Same
// manager-role gate as creating a commitment.
//
// UPDATED: EDIT now also accepts relatedGrievanceId, so a commitment can
// be linked to (or unlinked from) a grievance after creation — the field
// already existed in the schema and on create, but editing it was missing.

import { getVerifiedUser } from "../../_shared/get-verified-user.js";
import { canManageOfficeRecords, hasPermission } from "../../_shared/permissions.js";
import { recordActivity, loadActivityForEntity } from "../../_shared/activity-log.js";

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const id = params.id;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  if (!hasPermission(auth.user.role, "VIEW")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const row = await env.DB.prepare("SELECT * FROM commitments WHERE id = ?").bind(id).first();
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const audit = await loadActivityForEntity(env, "COMMITMENT", id);
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

  const row = await env.DB.prepare("SELECT * FROM commitments WHERE id = ?").bind(id).first();
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const body = await request.json();

  if (body.action === "EDIT") {
    const title = (body.title || "").trim();
    if (!title) {
      return Response.json({ error: "VALIDATION_ERROR", message: "title is required" }, { status: 400 });
    }
    await env.DB.prepare(
      `UPDATE commitments SET title=?, description=?, due_date=?, related_grievance_id=? WHERE id=?`
    ).bind(title, body.description || null, body.dueDate || null, body.relatedGrievanceId || null, id).run();
    await recordActivity(env, { entityType: "COMMITMENT", entityId: id, action: "EDITED", detail: title, actorEmail: email, actorRole: role });

  } else if (body.action === "COMPLETE") {
    await env.DB.prepare(
      `UPDATE commitments SET status='DONE', completed_at=datetime('now') WHERE id=?`
    ).bind(id).run();
    await recordActivity(env, { entityType: "COMMITMENT", entityId: id, action: "COMPLETED", detail: row.title, actorEmail: email, actorRole: role });

  } else {
    return Response.json({ error: "UNKNOWN_ACTION" }, { status: 400 });
  }

  const updated = await env.DB.prepare("SELECT * FROM commitments WHERE id = ?").bind(id).first();
  const audit = await loadActivityForEntity(env, "COMMITMENT", id);
  return Response.json({ ...updated, audit });
}

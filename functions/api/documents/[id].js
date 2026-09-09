// functions/api/documents/[id].js
//
// Single-document detail (with its audit trail) plus an EDIT action.
// Documents have no status workflow (unlike projects/commitments) — just
// the record itself, correctable after logging. Same manager-role gate.

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

  const row = await env.DB.prepare("SELECT * FROM documents WHERE id = ?").bind(id).first();
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const audit = await loadActivityForEntity(env, "DOCUMENT", id);
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

  const row = await env.DB.prepare("SELECT * FROM documents WHERE id = ?").bind(id).first();
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const body = await request.json();
  if (body.action !== "EDIT") {
    return Response.json({ error: "UNKNOWN_ACTION" }, { status: 400 });
  }

  const title = (body.title || "").trim();
  if (!title) {
    return Response.json({ error: "VALIDATION_ERROR", message: "title is required" }, { status: 400 });
  }
  await env.DB.prepare(
    `UPDATE documents SET title=?, source_department=?, doc_type=?, received_date=?, summary=? WHERE id=?`
  ).bind(
    title, body.sourceDepartment || null, body.docType || null,
    body.receivedDate || null, body.summary || null, id
  ).run();
  await recordActivity(env, { entityType: "DOCUMENT", entityId: id, action: "EDITED", detail: title, actorEmail: email, actorRole: role });

  const updated = await env.DB.prepare("SELECT * FROM documents WHERE id = ?").bind(id).first();
  const audit = await loadActivityForEntity(env, "DOCUMENT", id);
  return Response.json({ ...updated, audit });
}

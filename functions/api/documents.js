// functions/api/documents.js
//
// Government orders, circulars, and notices the office receives — logged
// so staff can find past documents and My Day can surface newly-received
// ones with a deadline attached (e.g. a grant application window).

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
    "SELECT * FROM documents ORDER BY created_at DESC"
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
    `INSERT INTO documents (id, title, source_department, doc_type, received_date, summary, raw_text, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id, title, body.sourceDepartment || null, body.docType || null,
    body.receivedDate || null, body.summary || null, body.rawText || null, email
  ).run();

  await recordActivity(env, {
    entityType: "DOCUMENT", entityId: id, action: "LOGGED", detail: title,
    actorEmail: email, actorRole: role,
  });

  return Response.json({ id });
}

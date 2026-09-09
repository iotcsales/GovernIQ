// functions/api/projects.js
//
// Government projects/schemes tracked by the office (roads, borewells,
// community halls, etc.) — a new office-record type alongside grievances.
// Same auth pattern as everywhere else in this app: role comes only from
// the verified session (getVerifiedUser), never from anything the browser
// sends.

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
    "SELECT * FROM projects ORDER BY created_at DESC"
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
  const status = body.status || "PLANNED";
  const id = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO projects (id, title, description, department, status, location_text, sanctioned_date, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id, title, body.description || null, body.department || null,
    status, body.locationText || null, body.sanctionedDate || null, email
  ).run();

  await recordActivity(env, {
    entityType: "PROJECT", entityId: id, action: "CREATED", detail: title,
    actorEmail: email, actorRole: role,
  });

  return Response.json({ id, status });
}

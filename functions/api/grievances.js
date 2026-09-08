// GovernIQ — Grievances endpoint (server-side role/scope enforcement)
//
// Role now comes ONLY from the verified Cloudflare Access JWT + D1 `users`
// lookup — never from anything the browser sends. This closes two gaps at
// once: (1) citizen_name/citizen_contact are stripped from the response
// unless the caller's REAL role has SENSITIVE_DATA_ACCESS, and (2) FIELD_TEAM's
// "only see assigned cases" scope is now actually enforced, not just defined.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission, PERMISSIONS } from "../_shared/permissions.js";
import { recordAudit } from "../_shared/grievance-data.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) {
    return Response.json({ error: auth.error }, { status: auth.status });
  }
  const { role, email } = auth.user;

  if (!hasPermission(role, "VIEW")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const { results } = await env.DB.prepare(
    "SELECT * FROM grievances ORDER BY created_at DESC"
  ).all();

  const scope = (PERMISSIONS[role] || {}).scope;
  const rows = scope === "OWN_ASSIGNED"
    ? results.filter((g) => g.assigned_to === email)
    : results;

  // Batch-fetch tasks for every visible case in one query, so "My Day"'s
  // overdue-task count stays accurate without an N+1 query per case.
  let tasksByGrievance = {};
  if (rows.length > 0) {
    const ids = rows.map((r) => r.id);
    const placeholders = ids.map(() => "?").join(",");
    const { results: taskRows } = await env.DB.prepare(
      `SELECT grievance_id, id, title, due_date, status FROM grievance_tasks WHERE grievance_id IN (${placeholders})`
    ).bind(...ids).all();
    for (const t of taskRows) {
      const list = tasksByGrievance[t.grievance_id] || (tasksByGrievance[t.grievance_id] = []);
      list.push({ id: t.id, title: t.title, dueDate: t.due_date || "no date set", status: t.status });
    }
  }

  const canSeeSensitive = hasPermission(role, "SENSITIVE_DATA_ACCESS");
  const sanitized = rows.map((g) => {
    const withTasks = { ...g, tasks: tasksByGrievance[g.id] || [] };
    if (canSeeSensitive) return withTasks;
    const { citizen_name, citizen_contact, ...rest } = withTasks;
    return rest;
  });

  return Response.json(sanitized);
}

export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) {
    return Response.json({ error: auth.error }, { status: auth.status });
  }
  const { role, email } = auth.user;

  if (!hasPermission(role, "CREATE")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const body = await request.json();
  const id = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO grievances (id, title, description, location_text, citizen_name, citizen_contact, status, created_by)
     VALUES (?, ?, ?, ?, ?, ?, 'DRAFT', ?)`
  ).bind(
    id,
    body.title,
    body.description,
    body.locationText || null,
    body.citizenName || null,
    body.citizenContact || null,
    email // server-derived from the verified session — never trust a client-sent createdBy
  ).run();

  // Real, persisted audit trail entry — previously synthesized client-side
  // as a fake "Loaded from D1" line on every page load; now an actual row
  // that survives refreshes and different sessions.
  await recordAudit(env, {
    grievanceId: id,
    action: "CREATED",
    detail: "Draft saved by field intake — persisted to database",
    actorEmail: email,
    actorRole: role,
  });

  return Response.json({ id, status: "DRAFT" });
}

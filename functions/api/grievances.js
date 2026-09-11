// GovernIQ — Grievances endpoint (server-side role/scope enforcement)
//
// Role comes ONLY from the verified Cloudflare Access JWT + D1 `users`
// lookup — never from anything the browser sends.
//
// UPDATED (multi-assignee support, backlog item 3): the OWN_ASSIGNED scope
// filter (FIELD_TEAM's "only see my own cases" restriction) now also
// matches cases where the caller is a support assignee, not only the
// primary — pulled from grievance_assignees in one extra query rather than
// per-row, so this stays a single round trip regardless of list size.

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
  let rows = results;
  if (scope === "OWN_ASSIGNED") {
    const { results: teamRows } = await env.DB.prepare(
      "SELECT DISTINCT grievance_id FROM grievance_assignees WHERE user_email = ?"
    ).bind(email).all();
    const onMyTeam = new Set(teamRows.map((r) => r.grievance_id));
    rows = results.filter((g) => g.assigned_to === email || onMyTeam.has(g.id));
  }

  // Batch-fetch tasks and the full assignee team for every visible case in
  // two queries total, so "My Day"'s overdue-task count (and any UI that
  // wants to show the whole team, not just the primary) stays accurate
  // without an N+1 query per case.
  let tasksByGrievance = {};
  let assigneesByGrievance = {};
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

    const { results: assigneeRows } = await env.DB.prepare(
      `SELECT ga.grievance_id, ga.user_email, ga.role_on_case, u.name
       FROM grievance_assignees ga LEFT JOIN users u ON u.email = ga.user_email
       WHERE ga.grievance_id IN (${placeholders})`
    ).bind(...ids).all();
    for (const a of assigneeRows) {
      const list = assigneesByGrievance[a.grievance_id] || (assigneesByGrievance[a.grievance_id] = []);
      list.push({ email: a.user_email, name: a.name || a.user_email, roleOnCase: a.role_on_case });
    }
  }

  const canSeeSensitive = hasPermission(role, "SENSITIVE_DATA_ACCESS");
  const sanitized = rows.map((g) => {
    const withExtras = {
      ...g,
      tasks: tasksByGrievance[g.id] || [],
      assignees: assigneesByGrievance[g.id] || [],
    };
    if (canSeeSensitive) return withExtras;
    const { citizen_name, citizen_contact, ...rest } = withExtras;
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

  const description = (body.description || "").trim();
  if (!description) {
    return Response.json({ error: "VALIDATION_ERROR", message: "description is required" }, { status: 400 });
  }
  const title = (body.title && body.title.trim()) || description.slice(0, 80);

  const id = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO grievances (id, title, description, location_text, citizen_name, citizen_contact, status, created_by)
     VALUES (?, ?, ?, ?, ?, ?, 'DRAFT', ?)`
  ).bind(
    id,
    title,
    description,
    body.locationText || null,
    body.citizenName || null,
    body.citizenContact || null,
    email
  ).run();

  await recordAudit(env, {
    grievanceId: id,
    action: "CREATED",
    detail: "Draft saved by field intake — persisted to database",
    actorEmail: email,
    actorRole: role,
  });

  return Response.json({ id, title, status: "DRAFT" });
}

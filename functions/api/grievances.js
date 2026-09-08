// GovernIQ — Grievances endpoint (server-side role/scope enforcement)
//
// Role now comes ONLY from the verified Cloudflare Access JWT + D1 `users`
// lookup — never from anything the browser sends. This closes two gaps at
// once: (1) citizen_name/citizen_contact are stripped from the response
// unless the caller's REAL role has SENSITIVE_DATA_ACCESS, and (2) FIELD_TEAM's
// "only see assigned cases" scope is now actually enforced, not just defined.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission, PERMISSIONS } from "../_shared/permissions.js";

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

  const canSeeSensitive = hasPermission(role, "SENSITIVE_DATA_ACCESS");
  const sanitized = rows.map((g) => {
    if (canSeeSensitive) return g;
    const { citizen_name, citizen_contact, ...rest } = g;
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

  return Response.json({ id, status: "DRAFT" });
}

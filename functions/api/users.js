// functions/api/users.js
//
// Lists provisioned GovernIQ users — needed so the assignee picker can be
// a dropdown of real accounts instead of a free-text email field where a
// typo silently fails validation (ASSIGN already validates against this
// same `users` table; this just lets the frontend show the options instead
// of making someone type one from memory).
//
// Gated to ASSIGN permission — the same roles who can actually assign a
// case are the only ones who need to see the list of who to assign it to.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission } from "../_shared/permissions.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  if (!hasPermission(auth.user.role, "ASSIGN")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const { results } = await env.DB.prepare(
    "SELECT email, name, role FROM users ORDER BY name ASC"
  ).all();
  return Response.json(results);
}

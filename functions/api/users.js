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
//
// UPDATED: only roles that can actually work a case (EDIT: true in
// permissions.js) are returned as assignable — Representatives and
// Research Team have EDIT: false and were never meaningful assignees,
// since they can't add tasks/evidence or move status once assigned.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission } from "../_shared/permissions.js";

const ASSIGNABLE_ROLES = ["CHIEF_OF_STAFF", "OFFICE_ADMIN", "CONSTITUENCY_TEAM", "FIELD_TEAM"];

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  if (!hasPermission(auth.user.role, "ASSIGN")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const placeholders = ASSIGNABLE_ROLES.map(() => "?").join(",");
  const { results } = await env.DB.prepare(
    `SELECT email, name, role FROM users WHERE role IN (${placeholders}) ORDER BY name ASC`
  ).bind(...ASSIGNABLE_ROLES).all();
  return Response.json(results);
}
// functions/api/grievances/[id]/evidence.js
//
// Evidence records for a single grievance, persisted to D1. capturedBy is
// derived from the verified session server-side — never trusted from the
// browser, the same rule applied to createdBy elsewhere in this app.

import { getVerifiedUser } from "../../../_shared/get-verified-user.js";
import { hasPermission, PERMISSIONS } from "../../../_shared/permissions.js";
import { loadGrievance, loadGrievanceWithAudit, recordAudit } from "../../../_shared/grievance-data.js";

export async function onRequestPost(context) {
  const { request, env, params } = context;
  const id = params.id;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  const { role, email } = auth.user;

  const row = await loadGrievance(env, id);
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const scope = (PERMISSIONS[role] || {}).scope;
  if (scope === "OWN_ASSIGNED" && row.assigned_to !== email) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }
  if (!hasPermission(role, "EDIT")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const body = await request.json();
  const description = (body.description || "").trim();
  if (!description) return Response.json({ error: "VALIDATION_ERROR", message: "description is required" }, { status: 400 });

  const capturedBy = `${role} · ${email}`;
  await env.DB.prepare(
    `INSERT INTO grievance_evidence (id, grievance_id, description, source, captured_by) VALUES (?, ?, ?, 'Field capture', ?)`
  ).bind(crypto.randomUUID(), id, description, capturedBy).run();

  await recordAudit(env, { grievanceId: id, action: "EVIDENCE_ADDED", detail: description, actorEmail: email, actorRole: role });

  const result = await loadGrievanceWithAudit(env, id, hasPermission(role, "SENSITIVE_DATA_ACCESS"));
  return Response.json(result);
}

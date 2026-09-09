// functions/api/commitments/[id].js
//
// Marks a commitment complete. Same manager-role gate as creating one.

import { getVerifiedUser } from "../../_shared/get-verified-user.js";
import { canManageOfficeRecords } from "../../_shared/permissions.js";
import { recordActivity } from "../../_shared/activity-log.js";

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
  if (body.action !== "COMPLETE") {
    return Response.json({ error: "UNKNOWN_ACTION" }, { status: 400 });
  }

  await env.DB.prepare(
    `UPDATE commitments SET status='DONE', completed_at=datetime('now') WHERE id=?`
  ).bind(id).run();

  await recordActivity(env, {
    entityType: "COMMITMENT", entityId: id, action: "COMPLETED", detail: row.title,
    actorEmail: email, actorRole: role,
  });

  const updated = await env.DB.prepare("SELECT * FROM commitments WHERE id = ?").bind(id).first();
  return Response.json(updated);
}

// functions/api/grievances/[id].js
//
// Single-grievance detail (with a REAL audit trail, not the fake
// "Loaded from D1" line the browser used to synthesize) and the
// status-workflow actions: approve, reject, assign, status change,
// verify, close. Every action is permission-checked against the
// caller's server-verified role and persists to D1 — nothing here is
// held only in browser memory anymore.

import { getVerifiedUser } from "../../_shared/get-verified-user.js";
import { hasPermission, PERMISSIONS } from "../../_shared/permissions.js";

const VALID_TRANSITIONS = {
  DRAFT: ["PENDING_REVIEW"], PENDING_REVIEW: ["NEW", "REVIEW_REQUIRED"], REVIEW_REQUIRED: ["PENDING_REVIEW"],
  NEW: ["ASSIGNED"], ASSIGNED: ["IN_PROGRESS"],
  IN_PROGRESS: ["WAITING_ON_DEPARTMENT", "ESCALATED", "RESOLVED"],
  WAITING_ON_DEPARTMENT: ["IN_PROGRESS", "ESCALATED"], ESCALATED: ["IN_PROGRESS", "RESOLVED"],
  RESOLVED: ["VERIFIED"], VERIFIED: ["CLOSED"], CLOSED: ["REOPENED"], REOPENED: ["IN_PROGRESS"],
};
function isValidTransition(from, to) {
  const allowed = VALID_TRANSITIONS[from];
  return Array.isArray(allowed) && allowed.includes(to);
}

function sanitize(row, canSeeSensitive) {
  if (canSeeSensitive) return row;
  const { citizen_name, citizen_contact, ...rest } = row;
  return rest;
}

async function loadGrievance(env, id) {
  return env.DB.prepare("SELECT * FROM grievances WHERE id = ?").bind(id).first();
}

async function loadAudit(env, id) {
  const { results } = await env.DB.prepare(
    "SELECT action, detail, actor_email, actor_role, created_at FROM grievance_audit WHERE grievance_id = ? ORDER BY created_at ASC"
  ).bind(id).all();
  return results.map((r) => ({
    action: r.action,
    actor: `${r.actor_role} · ${r.actor_email}`,
    at: r.created_at,
    detail: r.detail || "",
  }));
}

async function recordAudit(env, { grievanceId, action, detail, actorEmail, actorRole }) {
  await env.DB.prepare(
    `INSERT INTO grievance_audit (id, grievance_id, action, detail, actor_email, actor_role) VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), grievanceId, action, detail || null, actorEmail, actorRole).run();
}

export async function onRequestGet(context) {
  const { request, env, params } = context;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  const { role, email } = auth.user;

  if (!hasPermission(role, "VIEW")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const row = await loadGrievance(env, params.id);
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const scope = (PERMISSIONS[role] || {}).scope;
  if (scope === "OWN_ASSIGNED" && row.assigned_to !== email) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const canSeeSensitive = hasPermission(role, "SENSITIVE_DATA_ACCESS");
  const audit = await loadAudit(env, params.id);
  return Response.json({ ...sanitize(row, canSeeSensitive), audit });
}

export async function onRequestPatch(context) {
  const { request, env, params } = context;
  const id = params.id;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return Response.json({ error: auth.error }, { status: auth.status });
  const { role, email } = auth.user;
  const actorMeta = { actorEmail: email, actorRole: role };

  const row = await loadGrievance(env, id);
  if (!row) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  const scope = (PERMISSIONS[role] || {}).scope;
  if (scope === "OWN_ASSIGNED" && row.assigned_to !== email) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const body = await request.json();
  const { action } = body;

  if (action === "APPROVE") {
    if (!hasPermission(role, "APPROVE")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!isValidTransition(row.status, "NEW")) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });
    const displayId = "GOV-GRV-2026-" + id.replace(/-/g, "").slice(0, 6).toUpperCase();
    const category = body.category || row.category;
    const authority = body.responsibleAuthority || row.responsible_authority;
    await env.DB.prepare(
      `UPDATE grievances SET status='NEW', category=?, responsible_authority=?, display_id=?, updated_at=datetime('now') WHERE id=?`
    ).bind(category, authority, displayId, id).run();
    await recordAudit(env, { grievanceId: id, action: "HUMAN_REVIEWED", detail: "Approved AI suggestion — official case opened", ...actorMeta });

  } else if (action === "REJECT") {
    if (!hasPermission(role, "APPROVE")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!isValidTransition(row.status, "REVIEW_REQUIRED")) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });
    await env.DB.prepare(`UPDATE grievances SET status='REVIEW_REQUIRED', updated_at=datetime('now') WHERE id=?`).bind(id).run();
    await recordAudit(env, { grievanceId: id, action: "SENT_BACK_FOR_CORRECTION", detail: "Reviewer rejected the AI suggestion", ...actorMeta });

  } else if (action === "ASSIGN") {
    if (!hasPermission(role, "ASSIGN")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!isValidTransition(row.status, "ASSIGNED")) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });
    const assignee = (body.assignedTo || "").trim() || "Unassigned staff";
    await env.DB.prepare(`UPDATE grievances SET status='ASSIGNED', assigned_to=?, updated_at=datetime('now') WHERE id=?`).bind(assignee, id).run();
    await recordAudit(env, { grievanceId: id, action: "ASSIGNED", detail: `Assigned to ${assignee}`, ...actorMeta });

  } else if (action === "STATUS_CHANGE") {
    if (!hasPermission(role, "EDIT")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    const newStatus = body.newStatus;
    if (newStatus === "VERIFIED" || newStatus === "CLOSED") {
      return Response.json({ error: "USE_DEDICATED_ACTION" }, { status: 400 });
    }
    if (!isValidTransition(row.status, newStatus)) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });
    await env.DB.prepare(`UPDATE grievances SET status=?, updated_at=datetime('now') WHERE id=?`).bind(newStatus, id).run();
    await recordAudit(env, { grievanceId: id, action: "STATUS_CHANGED", detail: `${row.status.replace(/_/g, " ")} → ${newStatus.replace(/_/g, " ")}`, ...actorMeta });

  } else if (action === "VERIFY") {
    if (!hasPermission(role, "VERIFY")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!isValidTransition(row.status, "VERIFIED")) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });
    await env.DB.prepare(`UPDATE grievances SET status='VERIFIED', updated_at=datetime('now') WHERE id=?`).bind(id).run();
    await recordAudit(env, { grievanceId: id, action: "VERIFIED", detail: "Outcome verified", ...actorMeta });

  } else if (action === "CLOSE") {
    if (!hasPermission(role, "CLOSE")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!isValidTransition(row.status, "CLOSED")) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });
    await env.DB.prepare(`UPDATE grievances SET status='CLOSED', updated_at=datetime('now') WHERE id=?`).bind(id).run();
    await recordAudit(env, { grievanceId: id, action: "CLOSED", detail: "Case closed", ...actorMeta });

  } else {
    return Response.json({ error: "UNKNOWN_ACTION" }, { status: 400 });
  }

  const updatedRow = await loadGrievance(env, id);
  const canSeeSensitive = hasPermission(role, "SENSITIVE_DATA_ACCESS");
  const audit = await loadAudit(env, id);
  return Response.json({ ...sanitize(updatedRow, canSeeSensitive), audit });
}

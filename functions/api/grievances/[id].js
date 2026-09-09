// functions/api/grievances/[id].js
//
// Single-grievance detail (with a REAL audit trail) and the status-workflow
// actions: approve, reject, assign, status change, verify, close, and now
// edit. Every action is permission-checked against the caller's
// server-verified role and persists to D1. APPROVE reads the AI suggestion
// that classification already stored server-side (ai_suggestion column)
// rather than trusting category/authority values sent by the browser at
// approval time.
//
// UPDATED: added an EDIT action so a typo in title/description/location
// (or citizen name/contact, for roles with Sensitive Data Access) made at
// intake can actually be corrected — previously grievances were the one
// entity in the app with no edit path at all, unlike Projects/Documents/
// Commitments. Citizen name/contact can only be changed by a caller whose
// REAL role has SENSITIVE_DATA_ACCESS — checked server-side, never trusting
// which inputs the browser chose to show.

import { getVerifiedUser } from "../../_shared/get-verified-user.js";
import { hasPermission, PERMISSIONS } from "../../_shared/permissions.js";
import { loadGrievance, loadGrievanceWithAudit, recordAudit } from "../../_shared/grievance-data.js";

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
  const result = await loadGrievanceWithAudit(env, params.id, canSeeSensitive);
  return Response.json(result);
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

    // The AI suggestion is read from what classification already persisted
    // server-side — never from anything the browser sends at approval time.
    let suggestion = null;
    try { suggestion = row.ai_suggestion ? JSON.parse(row.ai_suggestion) : null; } catch (e) { suggestion = null; }
    if (!suggestion) {
      return Response.json({ error: "NO_AI_SUGGESTION", message: "Classify this case before approving" }, { status: 409 });
    }

    const displayId = "GOV-GRV-2026-" + id.replace(/-/g, "").slice(0, 6).toUpperCase();
    await env.DB.prepare(
      `UPDATE grievances SET status='NEW', category=?, responsible_authority=?, display_id=?, updated_at=datetime('now') WHERE id=?`
    ).bind(suggestion.category, suggestion.authority, displayId, id).run();
    await recordAudit(env, { grievanceId: id, action: "HUMAN_REVIEWED", detail: "Approved AI suggestion — official case opened", ...actorMeta });

  } else if (action === "REJECT") {
    if (!hasPermission(role, "APPROVE")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!isValidTransition(row.status, "REVIEW_REQUIRED")) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });
    await env.DB.prepare(`UPDATE grievances SET status='REVIEW_REQUIRED', updated_at=datetime('now') WHERE id=?`).bind(id).run();
    await recordAudit(env, { grievanceId: id, action: "SENT_BACK_FOR_CORRECTION", detail: "Reviewer rejected the AI suggestion", ...actorMeta });

  } else if (action === "ASSIGN") {
    if (!hasPermission(role, "ASSIGN")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!isValidTransition(row.status, "ASSIGNED")) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });

    // Must be a real, provisioned GovernIQ email — not a free-text display
    // name. assigned_to is what the OWN_ASSIGNED scope filter matches
    // against elsewhere, so a typo or a plain name here would silently
    // hide the case from the person it was meant for.
    const assigneeEmail = (body.assignedTo || "").trim().toLowerCase();
    if (!assigneeEmail || !assigneeEmail.includes("@")) {
      return Response.json({ error: "VALIDATION_ERROR", message: "Enter the assignee's email address" }, { status: 400 });
    }
    const assigneeUser = await env.DB.prepare("SELECT email, name FROM users WHERE email = ?").bind(assigneeEmail).first();
    if (!assigneeUser) {
      return Response.json({ error: "ASSIGNEE_NOT_FOUND", message: "That email isn't a provisioned GovernIQ user" }, { status: 400 });
    }
    await env.DB.prepare(`UPDATE grievances SET status='ASSIGNED', assigned_to=?, updated_at=datetime('now') WHERE id=?`).bind(assigneeUser.email, id).run();
    await recordAudit(env, { grievanceId: id, action: "ASSIGNED", detail: `Assigned to ${assigneeUser.name} (${assigneeUser.email})`, ...actorMeta });

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

  } else if (action === "EDIT") {
    if (!hasPermission(role, "EDIT")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });

    const title = (body.title || "").trim();
    const description = (body.description || "").trim();
    if (!title || !description) {
      return Response.json({ error: "VALIDATION_ERROR", message: "title and description are required" }, { status: 400 });
    }

    // Citizen name/contact can only be changed by a caller whose REAL role
    // has SENSITIVE_DATA_ACCESS — checked here server-side, not just by
    // whether the frontend happened to show those inputs. Anyone else's
    // edit leaves the existing stored values untouched.
    const canEditSensitive = hasPermission(role, "SENSITIVE_DATA_ACCESS");
    const citizenName = canEditSensitive && body.citizenName !== undefined ? body.citizenName : row.citizen_name;
    const citizenContact = canEditSensitive && body.citizenContact !== undefined ? body.citizenContact : row.citizen_contact;

    await env.DB.prepare(
      `UPDATE grievances SET title=?, description=?, location_text=?, citizen_name=?, citizen_contact=?, updated_at=datetime('now') WHERE id=?`
    ).bind(title, description, body.locationText || null, citizenName, citizenContact, id).run();
    await recordAudit(env, { grievanceId: id, action: "EDITED", detail: "Case details corrected", ...actorMeta });

  } else {
    return Response.json({ error: "UNKNOWN_ACTION" }, { status: 400 });
  }

  const canSeeSensitive = hasPermission(role, "SENSITIVE_DATA_ACCESS");
  const result = await loadGrievanceWithAudit(env, id, canSeeSensitive);
  return Response.json(result);
}

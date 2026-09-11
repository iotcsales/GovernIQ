// functions/api/grievances/[id].js
//
// Single-grievance detail (with a REAL audit trail) and the status-workflow
// actions: approve, reject, assign, status change, verify, close, and edit.
// Every action is permission-checked against the caller's server-verified
// role and persists to D1.
//
// UPDATED (multi-assignee support, backlog item 3): ASSIGN still sets the
// primary assignee (grievances.assigned_to), but now does so through
// upsertPrimaryAssignee, which keeps a matching 'primary' row in
// grievance_assignees in sync — the previous primary is demoted to
// 'support' rather than dropped from the case. Two new actions,
// ADD_ASSIGNEE and REMOVE_ASSIGNEE, manage the rest of the team (support
// assignees) without touching who's primary. The OWN_ASSIGNED scope check
// (used by FIELD_TEAM) now also recognizes support assignees, not just the
// primary, so someone looped in to help on a case can actually see it.

import { getVerifiedUser } from "../../_shared/get-verified-user.js";
import { hasPermission, PERMISSIONS } from "../../_shared/permissions.js";
import {
  loadGrievance, loadGrievanceWithAudit, recordAudit,
  isUserAssignedToGrievance, upsertPrimaryAssignee, addSupportAssignee, removeSupportAssignee,
} from "../../_shared/grievance-data.js";

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

// Statuses in which a case can be (re)assigned or have its support team
// changed. Same list for both — adding/removing a support assignee makes
// no sense on a case that isn't open yet, or one that's already wrapping up.
const ASSIGNABLE_STATUSES = ["NEW", "ASSIGNED", "IN_PROGRESS", "WAITING_ON_DEPARTMENT", "ESCALATED", "REOPENED"];

// Looks up a real, provisioned user by email and confirms they're a role
// that can actually work a case (EDIT: true) — the same standard
// functions/api/users.js already applies to who appears in the assignee
// dropdown. Shared by ASSIGN and ADD_ASSIGNEE so a support assignee can
// never be someone who couldn't have been the primary either.
async function findAssignableUser(env, email) {
  const user = await env.DB.prepare("SELECT email, name, role FROM users WHERE email = ?").bind(email).first();
  if (!user) return { error: "ASSIGNEE_NOT_FOUND" };
  if (!hasPermission(user.role, "EDIT")) return { error: "NOT_ASSIGNABLE_ROLE" };
  return { user };
}

async function checkScope(env, role, email, row) {
  const scope = (PERMISSIONS[role] || {}).scope;
  if (scope !== "OWN_ASSIGNED") return true;
  if (row.assigned_to === email) return true;
  return isUserAssignedToGrievance(env, row.id, email);
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

  if (!(await checkScope(env, role, email, row))) {
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

  if (!(await checkScope(env, role, email, row))) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  const body = await request.json();
  const { action } = body;

  if (action === "APPROVE") {
    if (!hasPermission(role, "APPROVE")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!isValidTransition(row.status, "NEW")) return Response.json({ error: "INVALID_TRANSITION" }, { status: 409 });

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
    if (!ASSIGNABLE_STATUSES.includes(row.status)) {
      return Response.json({
        error: "INVALID_TRANSITION",
        message: "Case must be approved and still open to assign — approve it first, or reopen it if it's already resolved/closed",
      }, { status: 409 });
    }

    const assigneeEmail = (body.assignedTo || "").trim().toLowerCase();
    if (!assigneeEmail || !assigneeEmail.includes("@")) {
      return Response.json({ error: "VALIDATION_ERROR", message: "Enter the assignee's email address" }, { status: 400 });
    }
    const lookup = await findAssignableUser(env, assigneeEmail);
    if (lookup.error === "ASSIGNEE_NOT_FOUND") {
      return Response.json({ error: "ASSIGNEE_NOT_FOUND", message: "That email isn't a provisioned GovernIQ user" }, { status: 400 });
    }
    if (lookup.error === "NOT_ASSIGNABLE_ROLE") {
      return Response.json({ error: "NOT_ASSIGNABLE_ROLE", message: "That role can't be assigned a case to work" }, { status: 400 });
    }
    const assigneeUser = lookup.user;

    const previousAssignee = row.assigned_to || null;
    if (previousAssignee === assigneeUser.email) {
      return Response.json({ error: "VALIDATION_ERROR", message: "That case is already assigned to this person" }, { status: 400 });
    }

    const isFirstAssignment = row.status === "NEW";
    const nextStatus = isFirstAssignment ? "ASSIGNED" : row.status;

    await env.DB.prepare(
      `UPDATE grievances SET status=?, assigned_to=?, updated_at=datetime('now') WHERE id=?`
    ).bind(nextStatus, assigneeUser.email, id).run();
    // Keeps grievance_assignees in sync: the old primary (if any) is
    // demoted to 'support' rather than dropped from the case.
    await upsertPrimaryAssignee(env, id, assigneeUser.email, email);

    if (previousAssignee) {
      await recordAudit(env, {
        grievanceId: id, action: "REASSIGNED",
        detail: `Reassigned from ${previousAssignee} to ${assigneeUser.name} (${assigneeUser.email}) — ${previousAssignee} stays on the case as support`,
        ...actorMeta,
      });
    } else {
      await recordAudit(env, {
        grievanceId: id, action: "ASSIGNED",
        detail: `Assigned to ${assigneeUser.name} (${assigneeUser.email})`,
        ...actorMeta,
      });
    }

  } else if (action === "ADD_ASSIGNEE") {
    if (!hasPermission(role, "ASSIGN")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });
    if (!ASSIGNABLE_STATUSES.includes(row.status)) {
      return Response.json({ error: "INVALID_TRANSITION", message: "Case must be open to add someone to it" }, { status: 409 });
    }

    const supportEmail = (body.assigneeEmail || "").trim().toLowerCase();
    if (!supportEmail || !supportEmail.includes("@")) {
      return Response.json({ error: "VALIDATION_ERROR", message: "Enter the person's email address" }, { status: 400 });
    }
    const lookup = await findAssignableUser(env, supportEmail);
    if (lookup.error === "ASSIGNEE_NOT_FOUND") {
      return Response.json({ error: "ASSIGNEE_NOT_FOUND", message: "That email isn't a provisioned GovernIQ user" }, { status: 400 });
    }
    if (lookup.error === "NOT_ASSIGNABLE_ROLE") {
      return Response.json({ error: "NOT_ASSIGNABLE_ROLE", message: "That role can't be added to a case's team" }, { status: 400 });
    }
    const supportUser = lookup.user;

    if (row.assigned_to === supportUser.email) {
      return Response.json({ error: "VALIDATION_ERROR", message: "That person is already the primary assignee on this case" }, { status: 400 });
    }

    await addSupportAssignee(env, id, supportUser.email, email);
    await recordAudit(env, {
      grievanceId: id, action: "TEAM_MEMBER_ADDED",
      detail: `Added ${supportUser.name} (${supportUser.email}) to the case team`,
      ...actorMeta,
    });

  } else if (action === "REMOVE_ASSIGNEE") {
    if (!hasPermission(role, "ASSIGN")) return Response.json({ error: "FORBIDDEN" }, { status: 403 });

    const removeEmail = (body.assigneeEmail || "").trim().toLowerCase();
    if (!removeEmail) {
      return Response.json({ error: "VALIDATION_ERROR", message: "Specify which person to remove" }, { status: 400 });
    }
    if (removeEmail === row.assigned_to) {
      return Response.json({
        error: "VALIDATION_ERROR",
        message: "Can't remove the primary assignee this way — reassign the case to someone else first",
      }, { status: 400 });
    }

    await removeSupportAssignee(env, id, removeEmail);
    await recordAudit(env, {
      grievanceId: id, action: "TEAM_MEMBER_REMOVED",
      detail: `Removed ${removeEmail} from the case team`,
      ...actorMeta,
    });

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

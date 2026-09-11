// functions/api/grievances/[id]/tasks.js
//
// Tasks for a single grievance, persisted to D1.
//
// UPDATED (multi-assignee support, backlog item 3): tasks can now have
// their own assignees, independent of who's on the parent grievance's
// team — e.g. a specific task within a case can be handed to one field
// officer even if someone else is the case's primary. New ADD_ASSIGNEE /
// REMOVE_ASSIGNEE actions manage this; COMPLETE is unchanged. The access
// check now also recognizes support assignees on the parent grievance
// (via isUserAssignedToGrievance), not just its primary, matching the
// same widened scope rule used in [id].js and grievances.js.

import { getVerifiedUser } from "../../../_shared/get-verified-user.js";
import { hasPermission, PERMISSIONS } from "../../../_shared/permissions.js";
import {
  loadGrievance, loadGrievanceWithAudit, recordAudit,
  isUserAssignedToGrievance, addTaskAssignee, removeTaskAssignee,
} from "../../../_shared/grievance-data.js";

async function checkAccess(request, env, id) {
  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) return { error: Response.json({ error: auth.error }, { status: auth.status }) };
  const { role, email } = auth.user;

  const row = await loadGrievance(env, id);
  if (!row) return { error: Response.json({ error: "NOT_FOUND" }, { status: 404 }) };

  const scope = (PERMISSIONS[role] || {}).scope;
  if (scope === "OWN_ASSIGNED") {
    const onTeam = row.assigned_to === email || (await isUserAssignedToGrievance(env, id, email));
    if (!onTeam) {
      return { error: Response.json({ error: "FORBIDDEN" }, { status: 403 }) };
    }
  }
  if (!hasPermission(role, "EDIT")) {
    return { error: Response.json({ error: "FORBIDDEN" }, { status: 403 }) };
  }
  return { role, email, row };
}

export async function onRequestPost(context) {
  const { request, env, params } = context;
  const id = params.id;

  const access = await checkAccess(request, env, id);
  if (access.error) return access.error;
  const { role, email } = access;

  const body = await request.json();
  const title = (body.title || "").trim();
  if (!title) return Response.json({ error: "VALIDATION_ERROR", message: "title is required" }, { status: 400 });
  const dueDate = body.dueDate || null;

  await env.DB.prepare(
    `INSERT INTO grievance_tasks (id, grievance_id, title, due_date, status, created_by) VALUES (?, ?, ?, ?, 'OPEN', ?)`
  ).bind(crypto.randomUUID(), id, title, dueDate, email).run();

  await recordAudit(env, { grievanceId: id, action: "TASK_CREATED", detail: title, actorEmail: email, actorRole: role });

  const result = await loadGrievanceWithAudit(env, id, hasPermission(role, "SENSITIVE_DATA_ACCESS"));
  return Response.json(result);
}

export async function onRequestPatch(context) {
  const { request, env, params } = context;
  const id = params.id;

  const access = await checkAccess(request, env, id);
  if (access.error) return access.error;
  const { role, email } = access;

  const body = await request.json();
  const { taskId, action } = body;

  const task = await env.DB.prepare("SELECT id, title, grievance_id FROM grievance_tasks WHERE id = ? AND grievance_id = ?").bind(taskId, id).first();
  if (!task) return Response.json({ error: "NOT_FOUND" }, { status: 404 });

  if (action === "COMPLETE") {
    await env.DB.prepare(
      `UPDATE grievance_tasks SET status='COMPLETED', completed_at=datetime('now') WHERE id=?`
    ).bind(taskId).run();
    await recordAudit(env, { grievanceId: id, action: "TASK_COMPLETED", detail: task.title, actorEmail: email, actorRole: role });

  } else if (action === "ADD_ASSIGNEE") {
    const assigneeEmail = (body.assigneeEmail || "").trim().toLowerCase();
    if (!assigneeEmail || !assigneeEmail.includes("@")) {
      return Response.json({ error: "VALIDATION_ERROR", message: "Enter the person's email address" }, { status: 400 });
    }
    const user = await env.DB.prepare("SELECT email, name, role FROM users WHERE email = ?").bind(assigneeEmail).first();
    if (!user) {
      return Response.json({ error: "ASSIGNEE_NOT_FOUND", message: "That email isn't a provisioned GovernIQ user" }, { status: 400 });
    }
    if (!hasPermission(user.role, "EDIT")) {
      return Response.json({ error: "NOT_ASSIGNABLE_ROLE", message: "That role can't be assigned a task" }, { status: 400 });
    }
    await addTaskAssignee(env, taskId, user.email, email);
    await recordAudit(env, { grievanceId: id, action: "TASK_ASSIGNEE_ADDED", detail: `${user.name} (${user.email}) added to task "${task.title}"`, actorEmail: email, actorRole: role });

  } else if (action === "REMOVE_ASSIGNEE") {
    const assigneeEmail = (body.assigneeEmail || "").trim().toLowerCase();
    if (!assigneeEmail) {
      return Response.json({ error: "VALIDATION_ERROR", message: "Specify which person to remove" }, { status: 400 });
    }
    await removeTaskAssignee(env, taskId, assigneeEmail);
    await recordAudit(env, { grievanceId: id, action: "TASK_ASSIGNEE_REMOVED", detail: `${assigneeEmail} removed from task "${task.title}"`, actorEmail: email, actorRole: role });

  } else {
    return Response.json({ error: "UNKNOWN_ACTION" }, { status: 400 });
  }

  const result = await loadGrievanceWithAudit(env, id, hasPermission(role, "SENSITIVE_DATA_ACCESS"));
  return Response.json(result);
}

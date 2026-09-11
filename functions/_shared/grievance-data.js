// functions/_shared/grievance-data.js
//
// Shared D1 helpers for a single grievance and its audit trail. Every
// endpoint that reads or writes a grievance uses these, so the shape of
// "sanitized row + audit" is identical everywhere it's returned, and the
// PII-stripping rule lives in exactly one place.
//
// UPDATED: added multi-assignee support (backlog item 3). grievances.
// assigned_to remains the fast, denormalized "primary assignee" column —
// every existing read path (scope filtering, list views, the old Assign
// panel) keeps working unchanged. grievance_assignees is the real source
// of truth underneath it: upsertPrimaryAssignee keeps assigned_to and the
// 'primary' row in grievance_assignees in sync in one place, so they can
// never drift apart. addSupportAssignee/removeSupportAssignee manage the
// rest of the team, who don't touch assigned_to at all.

export function sanitizeGrievance(row, canSeeSensitive) {
  if (!row) return row;
  if (canSeeSensitive) return row;
  const { citizen_name, citizen_contact, ...rest } = row;
  return rest;
}

export async function loadGrievance(env, id) {
  return env.DB.prepare("SELECT * FROM grievances WHERE id = ?").bind(id).first();
}

export async function loadAudit(env, id) {
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

export async function recordAudit(env, { grievanceId, action, detail, actorEmail, actorRole }) {
  await env.DB.prepare(
    `INSERT INTO grievance_audit (id, grievance_id, action, detail, actor_email, actor_role) VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), grievanceId, action, detail || null, actorEmail, actorRole).run();
}

// ---------------------------------------------------------------------
// Multi-assignee support (grievance-level team)
// ---------------------------------------------------------------------

export async function loadGrievanceAssignees(env, grievanceId) {
  const { results } = await env.DB.prepare(
    `SELECT ga.user_email, ga.role_on_case, ga.assigned_at, u.name, u.role
     FROM grievance_assignees ga LEFT JOIN users u ON u.email = ga.user_email
     WHERE ga.grievance_id = ?
     ORDER BY CASE ga.role_on_case WHEN 'primary' THEN 0 ELSE 1 END, ga.assigned_at ASC`
  ).bind(grievanceId).all();
  return results.map((r) => ({
    email: r.user_email,
    name: r.name || r.user_email,
    role: r.role || null,
    roleOnCase: r.role_on_case,
    assignedAt: r.assigned_at,
  }));
}

// Whether `email` is on this case's team at all — primary or support. Used
// by the OWN_ASSIGNED scope check so a support assignee (e.g. a field
// officer looped in to help) can see the case, not only the primary.
export async function isUserAssignedToGrievance(env, grievanceId, email) {
  const row = await env.DB.prepare(
    `SELECT 1 FROM grievance_assignees WHERE grievance_id = ? AND user_email = ? LIMIT 1`
  ).bind(grievanceId, email).first();
  return !!row;
}

// Sets `email` as the primary assignee: demotes whoever currently holds
// 'primary' (if anyone, and if it isn't already this person) to 'support'
// rather than removing them — a reassignment usually means someone else is
// now driving the case, not that the previous person had nothing to do
// with it. Also keeps grievances.assigned_to in sync in the same call, so
// callers never update one without the other.
export async function upsertPrimaryAssignee(env, grievanceId, email, assignedBy) {
  await env.DB.prepare(
    `UPDATE grievance_assignees SET role_on_case = 'support'
     WHERE grievance_id = ? AND role_on_case = 'primary' AND user_email != ?`
  ).bind(grievanceId, email).run();

  await env.DB.prepare(
    `INSERT INTO grievance_assignees (id, grievance_id, user_email, role_on_case, assigned_by)
     VALUES (?, ?, ?, 'primary', ?)
     ON CONFLICT(grievance_id, user_email) DO UPDATE SET
       role_on_case = 'primary', assigned_by = excluded.assigned_by, assigned_at = datetime('now')`
  ).bind(crypto.randomUUID(), grievanceId, email, assignedBy).run();
}

// Adds a support assignee without touching the primary. A no-op (not an
// error) if that person is already on the case in any role — re-adding an
// existing support assignee, or trying to "add" someone who's already
// primary, just leaves things as they are.
export async function addSupportAssignee(env, grievanceId, email, assignedBy) {
  await env.DB.prepare(
    `INSERT INTO grievance_assignees (id, grievance_id, user_email, role_on_case, assigned_by)
     VALUES (?, ?, ?, 'support', ?)
     ON CONFLICT(grievance_id, user_email) DO NOTHING`
  ).bind(crypto.randomUUID(), grievanceId, email, assignedBy).run();
}

// Removes a support assignee. Deliberately cannot remove the primary this
// way — the caller (functions/api/grievances/[id].js) checks the person's
// current role_on_case first and tells them to reassign instead if they
// try to remove the primary, since taking the primary off a case without
// naming a replacement would leave it with nobody driving it.
export async function removeSupportAssignee(env, grievanceId, email) {
  await env.DB.prepare(
    `DELETE FROM grievance_assignees WHERE grievance_id = ? AND user_email = ? AND role_on_case = 'support'`
  ).bind(grievanceId, email).run();
}

// ---------------------------------------------------------------------
// Tasks (now with their own, independent multi-assignee support)
// ---------------------------------------------------------------------

export async function loadTasks(env, id) {
  const { results } = await env.DB.prepare(
    "SELECT id, title, due_date, status FROM grievance_tasks WHERE grievance_id = ? ORDER BY created_at ASC"
  ).bind(id).all();
  if (results.length === 0) return [];

  const ids = results.map((t) => t.id);
  const placeholders = ids.map(() => "?").join(",");
  const { results: assigneeRows } = await env.DB.prepare(
    `SELECT ta.task_id, ta.user_email, u.name FROM task_assignees ta
     LEFT JOIN users u ON u.email = ta.user_email WHERE ta.task_id IN (${placeholders})`
  ).bind(...ids).all();

  const byTask = {};
  for (const a of assigneeRows) {
    (byTask[a.task_id] || (byTask[a.task_id] = [])).push({ email: a.user_email, name: a.name || a.user_email });
  }

  return results.map((t) => ({
    id: t.id,
    title: t.title,
    dueDate: t.due_date || "no date set",
    status: t.status,
    assignees: byTask[t.id] || [],
  }));
}

export async function addTaskAssignee(env, taskId, email, assignedBy) {
  await env.DB.prepare(
    `INSERT INTO task_assignees (id, task_id, user_email, assigned_by)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(task_id, user_email) DO NOTHING`
  ).bind(crypto.randomUUID(), taskId, email, assignedBy).run();
}

export async function removeTaskAssignee(env, taskId, email) {
  await env.DB.prepare(
    `DELETE FROM task_assignees WHERE task_id = ? AND user_email = ?`
  ).bind(taskId, email).run();
}

export async function loadEvidence(env, id) {
  const { results } = await env.DB.prepare(
    "SELECT id, description, source, captured_by FROM grievance_evidence WHERE grievance_id = ? ORDER BY created_at ASC"
  ).bind(id).all();
  return results.map((e) => ({ id: e.id, description: e.description, source: e.source, capturedBy: e.captured_by }));
}

export async function loadGrievanceWithAudit(env, id, canSeeSensitive) {
  const row = await loadGrievance(env, id);
  if (!row) return null;
  const [audit, tasks, evidence, assignees] = await Promise.all([
    loadAudit(env, id),
    loadTasks(env, id),
    loadEvidence(env, id),
    loadGrievanceAssignees(env, id),
  ]);
  return { ...sanitizeGrievance(row, canSeeSensitive), audit, tasks, evidence, assignees };
}

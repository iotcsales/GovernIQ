// functions/_shared/grievance-data.js
//
// Shared D1 helpers for a single grievance and its audit trail. Every
// endpoint that reads or writes a grievance uses these, so the shape of
// "sanitized row + audit" is identical everywhere it's returned, and the
// PII-stripping rule lives in exactly one place.

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

export async function loadTasks(env, id) {
  const { results } = await env.DB.prepare(
    "SELECT id, title, due_date, status FROM grievance_tasks WHERE grievance_id = ? ORDER BY created_at ASC"
  ).bind(id).all();
  return results.map((t) => ({ id: t.id, title: t.title, dueDate: t.due_date || "no date set", status: t.status }));
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
  const [audit, tasks, evidence] = await Promise.all([
    loadAudit(env, id),
    loadTasks(env, id),
    loadEvidence(env, id),
  ]);
  return { ...sanitizeGrievance(row, canSeeSensitive), audit, tasks, evidence };
}

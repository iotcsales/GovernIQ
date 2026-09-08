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

export async function loadGrievanceWithAudit(env, id, canSeeSensitive) {
  const row = await loadGrievance(env, id);
  if (!row) return null;
  const audit = await loadAudit(env, id);
  return { ...sanitizeGrievance(row, canSeeSensitive), audit };
}

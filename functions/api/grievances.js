export async function onRequestGet(context) {
  const { env } = context;
  const { results } = await env.DB.prepare(
    "SELECT * FROM grievances ORDER BY created_at DESC"
  ).all();
  return Response.json(results);
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const body = await request.json();
  const id = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO grievances (id, title, description, location_text, citizen_name, citizen_contact, status, created_by)
     VALUES (?, ?, ?, ?, ?, ?, 'DRAFT', ?)`
  ).bind(
    id,
    body.title,
    body.description,
    body.locationText || null,
    body.citizenName || null,
    body.citizenContact || null,
    body.createdBy || null
  ).run();

  return Response.json({ id, status: "DRAFT" });
}
// GovernIQ — Ask GovernIQ endpoint (server-side, real AI Gateway)
//
// Queries D1 directly for office context across all four record types —
// grievances, projects, documents, commitments — rather than trusting
// whatever context string the browser might send; the browser only sends
// the QUESTION. Whether the answer may include citizen names comes from
// the caller's verified role, looked up server-side — never from a client
// flag. Response is a structured shape (answer/why/evidence/confidence/
// missing/next-step), matching the case-detail AI suggestion's honesty
// standard: confidence is stated, and gaps are named rather than papered
// over.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission } from "../_shared/permissions.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) {
    return Response.json({ error: auth.error }, { status: auth.status });
  }
  if (!hasPermission(auth.user.role, "VIEW")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }
  const canSeeSensitive = hasPermission(auth.user.role, "SENSITIVE_DATA_ACCESS");

  if (!env.ANTHROPIC_API_KEY) {
    return Response.json({ error: "AI_PROVIDER_NOT_CONFIGURED" }, { status: 503 });
  }

  const body = await request.json();
  const { question } = body;
  if (!question) {
    return Response.json({ error: "VALIDATION_ERROR" }, { status: 400 });
  }

  const [grievanceRows, projectRows, documentRows, commitmentRows] = await Promise.all([
    env.DB.prepare("SELECT * FROM grievances ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT * FROM projects ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT * FROM documents ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT * FROM commitments ORDER BY due_date ASC").all(),
  ]);

  const grievanceLines = grievanceRows.results.map(g => {
    let line = `${g.display_id || g.id}: ${g.title}, status ${g.status}`;
    if (g.priority) line += `, priority ${g.priority}`;
    if (g.category) line += `, category ${g.category}`;
    if (g.responsible_authority) line += `, authority ${g.responsible_authority}`;
    if (canSeeSensitive) line += `, citizen ${g.citizen_name || "unknown"}`;
    return line;
  }).join("\n") || "No grievances yet.";

  const projectLines = projectRows.results.map(p =>
    `${p.title}: status ${p.status}, department ${p.department || "unknown"}${p.sanctioned_date ? ", sanctioned " + p.sanctioned_date : ""}`
  ).join("\n") || "No projects logged yet.";

  const documentLines = documentRows.results.map(d =>
    `${d.title}: from ${d.source_department || "unknown"}, received ${d.received_date || "unknown"}${d.summary ? " — " + d.summary : ""}`
  ).join("\n") || "No documents logged yet.";

  const commitmentLines = commitmentRows.results.map(c =>
    `${c.title}: status ${c.status}${c.due_date ? ", due " + c.due_date : ""}`
  ).join("\n") || "No commitments logged yet.";

  const systemPrompt = `You are GovernIQ, an AI Chief of Staff for an elected representative's office in India. Answer ONLY using the office data below. Never invent facts not present here. If something isn't covered, say so plainly under "whats_missing" rather than guessing.

GRIEVANCES:
${grievanceLines}

PROJECTS:
${projectLines}

DOCUMENTS:
${documentLines}

COMMITMENTS:
${commitmentLines}

If asked for something not available to this role (e.g. citizen names when sensitive data access is off), say so rather than omitting silently.

Respond ONLY as valid JSON, no markdown fences, no preamble, in this exact shape:
{"answer":"...", "why_it_matters":"...", "evidence":"...", "confidence":"High|Medium|Low", "whats_missing":"...", "recommended_next_step":"..."}`;

  let anthropicResponse;
  try {
    anthropicResponse = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-6",
        max_tokens: 700,
        system: systemPrompt,
        messages: [{ role: "user", content: question }],
      }),
    });
  } catch (e) {
    return Response.json({ error: "AI_UNAVAILABLE" }, { status: 502 });
  }

  if (!anthropicResponse.ok) {
    return Response.json({ error: "AI_UNAVAILABLE", status: anthropicResponse.status }, { status: 502 });
  }

  const data = await anthropicResponse.json();
  const text = (data.content || []).map(b => b.text || "").join("");

  let parsed;
  try {
    parsed = JSON.parse(text.replace(/```json|```/g, "").trim());
  } catch (e) {
    return Response.json({ error: "OUTPUT_VALIDATION_ERROR" }, { status: 502 });
  }

  return Response.json(parsed);
}

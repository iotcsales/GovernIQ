// GovernIQ — Ask GovernIQ endpoint (server-side, real AI Gateway)
// Queries D1 directly for office context, rather than trusting whatever
// context string the browser might send — the browser only sends the
// QUESTION. Whether the answer may include citizen names now comes from the
// caller's verified role, looked up server-side — never from a client flag.

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

  const { results } = await env.DB.prepare(
    "SELECT * FROM grievances ORDER BY created_at DESC"
  ).all();

  const contextLines = results.map(g => {
    let line = `${g.display_id || g.id}: ${g.title}, status ${g.status}`;
    if (g.priority) line += `, priority ${g.priority}`;
    if (canSeeSensitive) line += `, citizen ${g.citizen_name || "unknown"}`;
    return line;
  }).join("\n") || "No cases yet.";

  const systemPrompt = `Answer ONLY from this office data:\n${contextLines}\nIf asked for something not available to this role, say so. Respond ONLY as JSON: {"answer":"","confidence":"High|Medium|Low"}`;

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
        max_tokens: 500,
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

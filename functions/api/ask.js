// GovernIQ — Ask GovernIQ endpoint (server-side, real AI Gateway)
//
// Queries D1 directly for office context across all four record types —
// grievances, projects, documents, commitments — rather than trusting
// whatever context string the browser might send; the browser only sends
// the QUESTION (and now, optionally, recent conversation history — see
// below). Whether the answer may include citizen names comes from the
// caller's verified role, looked up server-side — never from a client
// flag. Response is a structured shape (answer/why/evidence/confidence/
// missing/next-step), matching the case-detail AI suggestion's honesty
// standard: confidence is stated, and gaps are named rather than papered
// over.
//
// UPDATED (P3, conversation memory): the browser may now send a `history`
// array of the last few {question, answer} turns from the current
// session's Ask conversation. These are replayed as real prior turns in
// the Anthropic messages array (not just pasted into the prompt as text),
// so a follow-up like "what about the one before that" actually resolves
// against what was asked and answered earlier — not just this one
// question in isolation. History is client-side and session-scoped (nothing
// is persisted server-side); this endpoint just needs to accept and use
// whatever the browser remembers for the current tab. The office-data
// system prompt is still rebuilt fresh on every call regardless of
// history length, so answers never drift from what's actually in D1 right
// now, even deep into a long conversation.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission } from "../_shared/permissions.js";

// Defensive caps on client-supplied history — the browser is expected to
// already trim to a handful of recent turns, but this endpoint doesn't
// trust that: an oversized or malformed history array is truncated/
// sanitized here rather than passed straight to the model.
const MAX_HISTORY_TURNS = 6;
const MAX_FIELD_LENGTH = 4000;

function truncate(str) {
  if (typeof str !== "string") return "";
  return str.length > MAX_FIELD_LENGTH ? str.slice(0, MAX_FIELD_LENGTH) : str;
}

// Turns a raw client-supplied history array into a validated list of
// {question, answer} pairs safe to replay to the model — anything
// malformed is dropped rather than causing the whole request to fail.
function sanitizeHistory(rawHistory) {
  if (!Array.isArray(rawHistory)) return [];
  return rawHistory
    .filter(turn => turn && typeof turn.question === "string" && turn.answer && typeof turn.answer === "object")
    .slice(-MAX_HISTORY_TURNS)
    .map(turn => ({
      question: truncate(turn.question),
      // Only the fields the model itself produces are replayed back to it —
      // this can't become a vector for injecting arbitrary assistant-turn
      // content, since every field is coerced to a string and truncated.
      answer: {
        answer: truncate(turn.answer.answer || ""),
        why_it_matters: truncate(turn.answer.why_it_matters || ""),
        evidence: truncate(turn.answer.evidence || ""),
        confidence: truncate(turn.answer.confidence || ""),
        whats_missing: truncate(turn.answer.whats_missing || ""),
        recommended_next_step: truncate(turn.answer.recommended_next_step || ""),
      },
    }));
}

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
  const history = sanitizeHistory(body.history);

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

This may be a follow-up question in an ongoing conversation — prior turns are included as real conversation history below. Use them to resolve references like "that one", "the one before", or "what about X" against what was actually asked and answered earlier. The office data above always reflects the current, live state — if something has changed since an earlier turn, answer based on the current data, not the earlier answer.

Respond ONLY as valid JSON, no markdown fences, no preamble, in this exact shape:
{"answer":"...", "why_it_matters":"...", "evidence":"...", "confidence":"High|Medium|Low", "whats_missing":"...", "recommended_next_step":"..."}`;

  // Replay sanitized prior turns as real conversation history, then the
  // new question — this is what actually gives the model "memory" of the
  // conversation, rather than just re-answering each question cold.
  const messages = [];
  history.forEach(turn => {
    messages.push({ role: "user", content: turn.question });
    messages.push({ role: "assistant", content: JSON.stringify(turn.answer) });
  });
  messages.push({ role: "user", content: question });

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
        messages,
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

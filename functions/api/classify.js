// GovernIQ — AI Classification endpoint (server-side, real AI Gateway)
// This runs on Cloudflare's servers, never in the browser. The API key
// lives only in env.ANTHROPIC_API_KEY (a Cloudflare secret) — it is never
// part of any response sent back to the client.
//
// The result of classification is now persisted to D1 (ai_suggestion column
// + status -> PENDING_REVIEW), not just held in browser memory — the
// approve step reads this stored value rather than trusting the browser.
//
// UPDATED: title is no longer collected from the intake form — the office
// now pastes one free-text description, and the AI suggests both a short
// case title and (if determinable) the location, alongside the existing
// category/severity/authority/action/confidence. Both are written back to
// the grievance record here, the same way the AI suggestion always has
// been — a human still reviews everything before APPROVE opens the case.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission } from "../_shared/permissions.js";
import { loadGrievance, loadGrievanceWithAudit, recordAudit } from "../_shared/grievance-data.js";

function redactText(text, citizenName, citizenContact) {
  if (!text) return text;
  let working = text;
  if (citizenName) working = working.split(citizenName).join("[CITIZEN_NAME]");
  if (citizenContact) working = working.split(citizenContact).join("[CITIZEN_CONTACT]");
  working = working.replace(/(?:\+91[-\s]?)?[6-9]\d{9}\b/g, "[CITIZEN_CONTACT]");
  working = working.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "[CITIZEN_CONTACT]");
  return working;
}

export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) {
    return Response.json({ error: auth.error }, { status: auth.status });
  }
  const { role, email } = auth.user;
  if (!hasPermission(role, "CREATE")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  if (!env.ANTHROPIC_API_KEY) {
    return Response.json({ error: "AI_PROVIDER_NOT_CONFIGURED" }, { status: 503 });
  }

  const body = await request.json();
  const { id, description, locationText, citizenName, citizenContact } = body;

  if (!id || !description) {
    return Response.json({ error: "VALIDATION_ERROR", message: "id and description are required" }, { status: 400 });
  }

  const existing = await loadGrievance(env, id);
  if (!existing) {
    return Response.json({ error: "NOT_FOUND" }, { status: 404 });
  }
  if (existing.status !== "DRAFT") {
    return Response.json({ error: "INVALID_TRANSITION", message: "Only DRAFT cases can be classified" }, { status: 409 });
  }

  // PII redaction — server-side, before anything leaves toward the provider.
  // Title is no longer part of the input; the AI now generates one as
  // output instead, from the same redacted description it already sees.
  const redactedDescription = redactText(description, citizenName, citizenContact);
  const redactedLocation = redactText(locationText, citizenName, citizenContact);
  const minimizedContent = `Description: ${redactedDescription}\nLocation: ${redactedLocation || "Not stated"}`;

  const systemPrompt = 'You are the GovernIQ grievance classifier. Input is PII-redacted, raw as received (phone, in person, or written). Respond ONLY as JSON: {"suggested_title":"","category":"","severity":"Low|Medium|High|Critical","authority":"","action":"","confidence":"High|Medium|Low","suggested_location":""}. suggested_title: a short, clear case title under 10 words, in plain language, no citizen name. suggested_location: the place name mentioned in the text, or "Information unavailable" if none is stated — never invent one.';

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
        messages: [{ role: "user", content: minimizedContent }],
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

  // Leaked-PII check — same principle as the AI Gateway Spec's P0 check:
  // if the raw citizen name/contact somehow appears in the model's output,
  // treat it as a failure rather than returning it.
  const outputText = JSON.stringify(parsed);
  if ((citizenName && outputText.includes(citizenName)) || (citizenContact && outputText.includes(citizenContact))) {
    return Response.json({ error: "OUTPUT_VALIDATION_ERROR", message: "PII leak detected in output" }, { status: 502 });
  }

  const suggestionToStore = { ...parsed, redactedSent: minimizedContent };

  // A blank/placeholder title should never make it into the stored record —
  // fall back to a truncated description rather than leave it empty.
  const finalTitle = (parsed.suggested_title && parsed.suggested_title.trim())
    || description.trim().slice(0, 80);

  // "Information unavailable" is meaningful to a human reviewer inside the
  // AI suggestion box, but storing that literal phrase as the case's actual
  // location field would look like a real place name later — store null
  // instead so the location field stays honestly empty until someone fills
  // it in.
  const locationLower = (parsed.suggested_location || "").trim().toLowerCase();
  const finalLocation = (parsed.suggested_location && locationLower !== "information unavailable" && locationLower !== "not stated")
    ? parsed.suggested_location.trim()
    : (locationText || null);

  await env.DB.prepare(
    `UPDATE grievances SET status='PENDING_REVIEW', title=?, location_text=?, priority=?, ai_suggestion=?, updated_at=datetime('now') WHERE id=?`
  ).bind(finalTitle, finalLocation, (parsed.severity || "").toUpperCase(), JSON.stringify(suggestionToStore), id).run();

  await recordAudit(env, {
    grievanceId: id,
    action: "AI_CLASSIFIED",
    detail: `Confidence: ${parsed.confidence} — classified server-side`,
    actorEmail: email,
    actorRole: role,
  });

  const result = await loadGrievanceWithAudit(env, id, hasPermission(role, "SENSITIVE_DATA_ACCESS"));
  return Response.json(result);
}

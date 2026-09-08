// GovernIQ — AI Classification endpoint (server-side, real AI Gateway)
// This runs on Cloudflare's servers, never in the browser. The API key
// lives only in env.ANTHROPIC_API_KEY (a Cloudflare secret) — it is never
// part of any response sent back to the client.

import { getVerifiedUser } from "../_shared/get-verified-user.js";
import { hasPermission } from "../_shared/permissions.js";

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

  // Real, server-verified role gate — classification is a step in creating
  // an official case, so it requires the same CREATE permission as actually
  // saving a grievance.
  const auth = await getVerifiedUser(request, env);
  if (!auth.ok) {
    return Response.json({ error: auth.error }, { status: auth.status });
  }
  if (!hasPermission(auth.user.role, "CREATE")) {
    return Response.json({ error: "FORBIDDEN" }, { status: 403 });
  }

  if (!env.ANTHROPIC_API_KEY) {
    return Response.json({ error: "AI_PROVIDER_NOT_CONFIGURED" }, { status: 503 });
  }

  const body = await request.json();
  const { title, description, locationText, citizenName, citizenContact } = body;

  if (!title || !description) {
    return Response.json({ error: "VALIDATION_ERROR", message: "title and description are required" }, { status: 400 });
  }

  // PII redaction — server-side, before anything leaves toward the provider.
  const redactedTitle = redactText(title, citizenName, citizenContact);
  const redactedDescription = redactText(description, citizenName, citizenContact);
  const redactedLocation = redactText(locationText, citizenName, citizenContact);
  const minimizedContent = `Title: ${redactedTitle}\nDescription: ${redactedDescription}\nLocation: ${redactedLocation}`;

  const systemPrompt = 'You are the GovernIQ grievance classifier. Input is PII-redacted. Respond ONLY as JSON: {"category":"","severity":"Low|Medium|High|Critical","authority":"","action":"","confidence":"High|Medium|Low"}';

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

  return Response.json({ ...parsed, redactedSent: minimizedContent });
}

// functions/api/me.js
//
// Returns the verified identity + real role for the currently signed-in
// Cloudflare Access user, looked up from the D1 `users` table. This is the
// source of truth the frontend and other endpoints should switch to instead
// of the browser-memory login dropdown.

import { verifyAccessJwt } from "../_shared/verify-access-jwt.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const token = request.headers.get("Cf-Access-Jwt-Assertion");
    const payload = await verifyAccessJwt(token, {
      teamDomain: env.ACCESS_TEAM_DOMAIN,
      aud: env.ACCESS_AUD,
    });

    const email = String(payload.email || "").toLowerCase();
    if (!email) {
      return new Response(JSON.stringify({ error: "No email in Access token" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const user = await env.DB
      .prepare("SELECT email, name, role, tenant_id FROM users WHERE email = ?")
      .bind(email)
      .first();

    if (!user) {
      return new Response(JSON.stringify({ error: "User not provisioned", email }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(
      JSON.stringify({
        email: user.email,
        name: user.name,
        role: user.role,
        tenant_id: user.tenant_id,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: err && err.message ? err.message : "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
}

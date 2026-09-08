// functions/_shared/get-verified-user.js
//
// Verifies the caller's Cloudflare Access JWT and looks up their real role
// from the D1 `users` table. Every endpoint that needs to know "who is
// this, and what can they do" calls this — never trusting a role or
// permission flag the browser sends, since the browser cannot be relied on
// to report its own access level honestly.
//
// This duplicates the JWT-verify + D1-lookup steps already in
// functions/api/me.js by design: me.js is a tested, working, deployed
// endpoint, and this file is deliberately kept separate from it so editing
// one can never accidentally change the behavior of the other.

import { verifyAccessJwt } from "./verify-access-jwt.js";

/**
 * @param {Request} request
 * @param {object} env - Pages Functions env (expects ACCESS_TEAM_DOMAIN, ACCESS_AUD, DB)
 * @returns {Promise<{ok: true, user: {email: string, name: string, role: string, tenant_id: string|null}} | {ok: false, status: number, error: string}>}
 */
export async function getVerifiedUser(request, env) {
  try {
    const token = request.headers.get("Cf-Access-Jwt-Assertion");
    const payload = await verifyAccessJwt(token, {
      teamDomain: env.ACCESS_TEAM_DOMAIN,
      aud: env.ACCESS_AUD,
    });

    const email = String(payload.email || "").toLowerCase();
    if (!email) {
      return { ok: false, status: 401, error: "No email in Access token" };
    }

    const user = await env.DB
      .prepare("SELECT email, name, role, tenant_id FROM users WHERE email = ?")
      .bind(email)
      .first();

    if (!user) {
      return { ok: false, status: 403, error: "User not provisioned" };
    }

    return { ok: true, user };
  } catch (err) {
    return { ok: false, status: 401, error: (err && err.message) || "Unauthorized" };
  }
}

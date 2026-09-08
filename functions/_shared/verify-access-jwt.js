// functions/_shared/verify-access-jwt.js
//
// Verifies a Cloudflare Access JWT (sent in the Cf-Access-Jwt-Assertion
// header) using native Web Crypto only — no npm dependency. Validates the
// RS256 signature against Cloudflare's published certs, plus issuer,
// audience, and expiry. Returns the decoded payload on success.

function base64UrlToUint8Array(base64Url) {
  const padding = "=".repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

function base64UrlDecodeToString(base64Url) {
  return new TextDecoder().decode(base64UrlToUint8Array(base64Url));
}

let cachedCerts = null;
let cachedCertsAt = 0;
const CERTS_TTL_MS = 60 * 60 * 1000; // 1 hour

async function getAccessCerts(teamDomain) {
  const now = Date.now();
  if (cachedCerts && now - cachedCertsAt < CERTS_TTL_MS) {
    return cachedCerts;
  }
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Access certs: ${res.status}`);
  }
  const data = await res.json();
  cachedCerts = data;
  cachedCertsAt = now;
  return data;
}

async function importKeyFromJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

/**
 * Verifies a Cloudflare Access JWT.
 *
 * @param {string} token - raw JWT from the Cf-Access-Jwt-Assertion header
 * @param {object} options
 * @param {string} options.teamDomain - e.g. "dark-mode-25a0.cloudflareaccess.com"
 * @param {string} options.aud - the Access application's AUD tag
 * @returns {Promise<object>} the verified JWT payload
 * @throws {Error} if the token is missing, malformed, expired, or invalid
 */
export async function verifyAccessJwt(token, { teamDomain, aud }) {
  if (!token) {
    throw new Error("Missing Access JWT");
  }
  if (!teamDomain || !aud) {
    throw new Error("Server misconfiguration: missing ACCESS_TEAM_DOMAIN or ACCESS_AUD");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT");
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = JSON.parse(base64UrlDecodeToString(headerB64));
  const payload = JSON.parse(base64UrlDecodeToString(payloadB64));

  if (header.alg !== "RS256") {
    throw new Error(`Unsupported JWT algorithm: ${header.alg}`);
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp < nowSeconds) {
    throw new Error("JWT expired");
  }
  if (payload.iss && !String(payload.iss).includes(teamDomain)) {
    throw new Error("JWT issuer mismatch");
  }
  const audClaim = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audClaim.includes(aud)) {
    throw new Error("JWT audience mismatch");
  }

  const certs = await getAccessCerts(teamDomain);
  const keys = certs.keys || certs.public_certs || [];
  const jwk = keys.find((k) => !header.kid || k.kid === header.kid) || keys[0];

  if (!jwk) {
    throw new Error("No matching signing key found for JWT");
  }

  const key = await importKeyFromJwk(jwk);
  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlToUint8Array(signatureB64);

  const isValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signature,
    signedData
  );

  if (!isValid) {
    throw new Error("JWT signature verification failed");
  }

  return payload;
}

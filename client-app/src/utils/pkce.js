/**
 * ============================================================
 * PKCE (Proof Key for Code Exchange) UTILITIES
 * ============================================================
 *
 * EDUCATIONAL NOTE - What is PKCE?
 *
 * PKCE (pronounced "pixy") is a security extension to OAuth 2.0
 * that protects against authorization code interception attacks.
 *
 * THE PROBLEM:
 * In the Authorization Code flow, an attacker who intercepts the
 * authorization code could exchange it for tokens. This is especially
 * risky for:
 * - Mobile apps (malicious apps can register for the same URL scheme)
 * - SPAs (code visible in browser history/logs)
 *
 * THE SOLUTION (PKCE):
 * 1. Client generates a random secret (code_verifier)
 * 2. Client sends hash of secret (code_challenge) in auth request
 * 3. Authorization server stores the hash
 * 4. Client sends original secret (code_verifier) when exchanging code
 * 5. Server verifies: SHA256(code_verifier) === stored hash
 *
 * WHY IT WORKS:
 * Even if attacker intercepts the code, they don't have the
 * code_verifier (it was only stored locally), so they can't
 * complete the token exchange.
 *
 * BEST PRACTICE:
 * Use PKCE for ALL clients, not just public ones.
 * It adds security with minimal overhead.
 * ============================================================
 */

const crypto = require('crypto');

/**
 * Generates a cryptographically random code verifier.
 *
 * SPECIFICATION (RFC 7636):
 * - Must be 43-128 characters
 * - Uses unreserved URI characters: [A-Z] [a-z] [0-9] - . _ ~
 * - base64url encoding naturally produces valid characters
 *
 * @returns {string} A random code verifier (43 characters)
 *
 * @example
 * const verifier = generateCodeVerifier();
 * // Returns something like: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
 */
function generateCodeVerifier() {
  // Generate 32 random bytes
  // base64url encoding produces ~43 characters (32 * 4/3)
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Generates a code challenge from a code verifier using SHA256.
 *
 * SPECIFICATION (RFC 7636):
 * code_challenge = BASE64URL(SHA256(code_verifier))
 *
 * The "S256" method (SHA256) is REQUIRED to be supported.
 * The "plain" method (no hashing) should only be used if
 * SHA256 is not available (very rare).
 *
 * @param {string} codeVerifier - The code verifier to hash
 * @returns {string} The base64url-encoded SHA256 hash
 *
 * @example
 * const challenge = generateCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
 * // Returns: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
 */
function generateCodeChallenge(codeVerifier) {
  return crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
}

/**
 * EDUCATIONAL EXAMPLE - PKCE in action:
 *
 * // Step 1: Before redirecting to authorization server
 * const codeVerifier = generateCodeVerifier();
 * const codeChallenge = generateCodeChallenge(codeVerifier);
 *
 * // Store verifier in session (server-side) or secure storage (client-side)
 * session.codeVerifier = codeVerifier;
 *
 * // Step 2: Include in authorization URL
 * const authUrl = `${authEndpoint}?
 *   client_id=${clientId}&
 *   code_challenge=${codeChallenge}&
 *   code_challenge_method=S256&
 *   ...`;
 *
 * // Step 3: In callback, include verifier in token request
 * const tokenResponse = await fetch(tokenEndpoint, {
 *   method: 'POST',
 *   body: new URLSearchParams({
 *     grant_type: 'authorization_code',
 *     code: authorizationCode,
 *     code_verifier: session.codeVerifier,  // <-- PKCE proof
 *     ...
 *   })
 * });
 */

module.exports = {
  generateCodeVerifier,
  generateCodeChallenge,
};

/**
 * ============================================================
 * TOKEN SERVICE - Managing OAuth2/OIDC Tokens
 * ============================================================
 *
 * This service handles all token-related operations:
 * - Exchanging authorization codes for tokens
 * - Validating ID tokens
 * - Refreshing access tokens
 * - Parsing JWTs for display
 *
 * TOKEN TYPES OVERVIEW:
 *
 * ACCESS TOKEN:
 *   Purpose: Authorize API requests
 *   Lifetime: Short (typically 5-15 minutes)
 *   Format: JWT or opaque string
 *   Usage: Authorization: Bearer <token>
 *
 * ID TOKEN (OIDC):
 *   Purpose: Prove user identity
 *   Lifetime: Short (matches access token)
 *   Format: Always JWT
 *   Usage: Client-side only, never send to APIs
 *
 * REFRESH TOKEN:
 *   Purpose: Get new access tokens
 *   Lifetime: Long (hours to days)
 *   Format: Opaque string
 *   Usage: Token endpoint only
 *
 * ============================================================
 */

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { oauthConfig } = require('../config/oauth');

/**
 * JWKS CLIENT
 *
 * JSON Web Key Set (JWKS) is how Keycloak publishes its public keys.
 * We use these keys to verify JWT signatures.
 *
 * FLOW:
 * 1. Decode JWT header to get key ID (kid)
 * 2. Fetch matching public key from JWKS endpoint
 * 3. Verify JWT signature with public key
 *
 * CACHING:
 * Keys are cached to avoid fetching on every verification.
 * Cache is refreshed when a new key ID is encountered.
 */
const jwks = jwksClient({
  jwksUri: oauthConfig.jwksUri,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 600000, // 10 minutes
});

/**
 * Exchanges an authorization code for tokens.
 *
 * TOKEN ENDPOINT REQUEST:
 *
 * This is a server-to-server (back-channel) request.
 * It's more secure than front-channel because:
 * - Client secret is used (never exposed to browser)
 * - Response contains tokens (not in URL)
 *
 * REQUIRED PARAMETERS:
 *   grant_type: "authorization_code"
 *   code: The authorization code from callback
 *   redirect_uri: Must match what was used in auth request
 *   client_id: Our application identifier
 *   client_secret: Our confidential credential
 *   code_verifier: PKCE proof
 *
 * @param {string} code - Authorization code from callback
 * @param {string} codeVerifier - PKCE code verifier
 * @returns {Promise<Object>} Token response
 */
async function exchangeCodeForTokens(code, codeVerifier) {
  const tokenUrl = oauthConfig.tokenEndpoint;

  /**
   * REQUEST BODY FORMAT
   *
   * Token endpoint requires application/x-www-form-urlencoded
   * URLSearchParams automatically handles encoding
   */
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: oauthConfig.redirectUri,
    client_id: oauthConfig.clientId,
    client_secret: oauthConfig.clientSecret,
    code_verifier: codeVerifier,
  });

  console.log('[TOKEN] Exchanging authorization code for tokens');
  console.log('[TOKEN] Token endpoint:', tokenUrl);

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    console.error('[TOKEN] Exchange failed:', errorBody);

    /**
     * COMMON ERRORS:
     * invalid_grant: Code expired, already used, or invalid
     * invalid_client: Client credentials wrong
     * invalid_request: Missing required parameter
     */
    throw new Error(
      `Token exchange failed: ${errorBody.error_description || errorBody.error || 'Unknown error'}`
    );
  }

  const tokens = await response.json();

  /**
   * TOKEN RESPONSE STRUCTURE:
   * {
   *   access_token: "eyJhbGc...",
   *   token_type: "Bearer",
   *   expires_in: 300,           // seconds until expiration
   *   refresh_token: "eyJhbGc...",
   *   id_token: "eyJhbGc...",    // OIDC only
   *   scope: "openid profile email"
   * }
   */
  console.log('[TOKEN] Exchange successful');
  console.log('[TOKEN] Token type:', tokens.token_type);
  console.log('[TOKEN] Expires in:', tokens.expires_in, 'seconds');
  console.log('[TOKEN] Scopes:', tokens.scope);

  return tokens;
}

/**
 * Validates an ID token.
 *
 * VALIDATION STEPS (all are REQUIRED):
 *
 * 1. DECODE & PARSE
 *    Extract header, payload, and signature
 *
 * 2. SIGNATURE VERIFICATION
 *    Verify using issuer's public key from JWKS
 *
 * 3. ISSUER VALIDATION
 *    iss claim must match expected issuer
 *
 * 4. AUDIENCE VALIDATION
 *    aud claim must contain our client_id
 *
 * 5. EXPIRATION CHECK
 *    exp claim must be in the future
 *
 * 6. NONCE VERIFICATION
 *    nonce claim must match what we sent
 *    (Prevents replay attacks)
 *
 * @param {string} idToken - The ID token JWT
 * @param {string} expectedNonce - The nonce we sent in auth request
 * @returns {Promise<Object>} Validated token claims
 */
async function validateIdToken(idToken, expectedNonce) {
  console.log('[TOKEN] Validating ID token');

  // Step 1: Decode header to get key ID
  const decoded = jwt.decode(idToken, { complete: true });

  if (!decoded) {
    throw new Error('Invalid ID token: Could not decode JWT');
  }

  console.log('[TOKEN] JWT header:', JSON.stringify(decoded.header));

  /**
   * KEY ID (kid)
   *
   * The header contains the key ID used to sign this token.
   * We use this to fetch the correct public key from JWKS.
   */
  const kid = decoded.header.kid;
  if (!kid) {
    throw new Error('Invalid ID token: No key ID in header');
  }

  // Step 2: Get public key from JWKS
  console.log('[TOKEN] Fetching signing key for kid:', kid);
  const key = await jwks.getSigningKey(kid);
  const publicKey = key.getPublicKey();

  // Step 3-5: Verify signature, issuer, audience, expiration
  /**
   * jwt.verify() performs:
   * - Signature verification
   * - Issuer validation (iss)
   * - Audience validation (aud)
   * - Expiration check (exp)
   * - Not-before check (nbf) if present
   */
  let claims;
  try {
    claims = jwt.verify(idToken, publicKey, {
      algorithms: ['RS256'],
      issuer: oauthConfig.issuer,
      audience: oauthConfig.clientId,
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('ID token has expired');
    }
    if (error.name === 'JsonWebTokenError') {
      throw new Error(`ID token invalid: ${error.message}`);
    }
    throw error;
  }

  // Step 6: Verify nonce
  /**
   * NONCE VERIFICATION
   *
   * This prevents replay attacks where an attacker
   * captures an ID token and tries to use it later.
   *
   * Each authentication request has a unique nonce,
   * so replayed tokens will fail this check.
   */
  if (claims.nonce !== expectedNonce) {
    console.error('[TOKEN] Nonce mismatch!');
    console.error('[TOKEN] Expected:', expectedNonce);
    console.error('[TOKEN] Received:', claims.nonce);
    throw new Error('Invalid nonce - possible replay attack');
  }

  console.log('[TOKEN] ID token validated successfully');
  console.log('[TOKEN] Subject (user ID):', claims.sub);
  console.log('[TOKEN] Issued at:', new Date(claims.iat * 1000).toISOString());
  console.log('[TOKEN] Expires at:', new Date(claims.exp * 1000).toISOString());

  return claims;
}

/**
 * Refreshes tokens using a refresh token.
 *
 * WHY REFRESH?
 *
 * Access tokens are short-lived for security.
 * Rather than making users re-authenticate frequently,
 * we use refresh tokens to get new access tokens.
 *
 * REFRESH TOKEN ROTATION:
 * Many servers return a new refresh token with each refresh.
 * Always store the new refresh token if provided.
 *
 * @param {string} refreshToken - The refresh token
 * @returns {Promise<Object>} New token response
 */
async function refreshTokens(refreshToken) {
  console.log('[TOKEN] Refreshing tokens');

  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: oauthConfig.clientId,
    client_secret: oauthConfig.clientSecret,
  });

  const response = await fetch(oauthConfig.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    console.error('[TOKEN] Refresh failed:', errorBody);

    /**
     * REFRESH TOKEN EXPIRATION:
     * If refresh fails with 'invalid_grant', the refresh token
     * has expired or been revoked. User must re-authenticate.
     */
    throw new Error(
      `Token refresh failed: ${errorBody.error_description || errorBody.error || 'Unknown error'}`
    );
  }

  const tokens = await response.json();
  console.log('[TOKEN] Tokens refreshed successfully');

  return tokens;
}

/**
 * Parses a JWT without verification (for display only).
 *
 * WARNING: Never trust unverified JWT claims for authorization!
 *
 * This is only for educational display purposes, to show
 * users what's inside their tokens.
 *
 * @param {string} token - The JWT to parse
 * @returns {Object|null} Parsed token structure or null if invalid
 */
function parseJwtForDisplay(token) {
  if (!token) return null;

  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) return null;

    return {
      header: decoded.header,
      payload: decoded.payload,
      // Show truncated signature for security
      signature: token.split('.')[2].substring(0, 32) + '...',
    };
  } catch (error) {
    console.error('[TOKEN] JWT parse error:', error.message);
    return null;
  }
}

/**
 * Fetches user info from the UserInfo endpoint.
 *
 * USERINFO vs ID TOKEN:
 *
 * ID Token:
 * - Received at authentication time
 * - Claims are frozen at that moment
 * - Doesn't require additional API call
 *
 * UserInfo Endpoint:
 * - Returns current user data
 * - Useful when data might have changed
 * - Requires valid access token
 *
 * @param {string} accessToken - Valid access token
 * @returns {Promise<Object>} User info claims
 */
async function getUserInfo(accessToken) {
  console.log('[TOKEN] Fetching user info');

  const response = await fetch(oauthConfig.userInfoEndpoint, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error('Access token invalid or expired');
    }
    throw new Error('Failed to fetch user info');
  }

  const userInfo = await response.json();
  console.log('[TOKEN] User info retrieved for:', userInfo.sub);

  return userInfo;
}

module.exports = {
  exchangeCodeForTokens,
  validateIdToken,
  refreshTokens,
  parseJwtForDisplay,
  getUserInfo,
};

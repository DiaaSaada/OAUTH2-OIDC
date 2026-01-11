/**
 * ============================================================
 * AUTHORIZATION CODE FLOW ROUTES
 * ============================================================
 *
 * This file implements the OAuth2 Authorization Code Flow with PKCE.
 *
 * FLOW OVERVIEW:
 *
 *   1. User clicks "Login" ──► GET /auth/login
 *   2. App generates security params (state, nonce, PKCE)
 *   3. App redirects to Keycloak authorization endpoint
 *   4. User authenticates with Keycloak
 *   5. Keycloak redirects to GET /auth/callback with code
 *   6. App exchanges code for tokens
 *   7. App validates ID token
 *   8. App creates authenticated session
 *
 * SECURITY MECHANISMS:
 *
 *   state  - Prevents CSRF attacks
 *   nonce  - Prevents ID token replay attacks
 *   PKCE   - Prevents authorization code interception
 *
 * ============================================================
 */

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const { oauthConfig } = require('../config/oauth');
const { generateCodeVerifier, generateCodeChallenge } = require('../utils/pkce');
const tokenService = require('../services/tokenService');

/**
 * GET /auth/login
 *
 * Initiates the Authorization Code Flow by redirecting to Keycloak.
 *
 * WHAT HAPPENS:
 * 1. Generate random state (CSRF protection)
 * 2. Generate random nonce (replay attack prevention)
 * 3. Generate PKCE code_verifier and code_challenge
 * 4. Store all in session for verification later
 * 5. Redirect to Keycloak authorization endpoint
 *
 * QUERY PARAMETERS (optional):
 *   returnTo - URL to redirect after successful login
 */
router.get('/login', (req, res) => {
  // --------------------------------------------------------
  // Generate Security Parameters
  // --------------------------------------------------------

  /**
   * STATE PARAMETER
   *
   * WHAT: Random, unpredictable value
   * WHY: Prevents Cross-Site Request Forgery (CSRF) attacks
   * HOW: We send it to Keycloak, Keycloak returns it in callback,
   *      we verify it matches what we stored.
   *
   * ATTACK PREVENTED:
   * Without state, attacker could craft a malicious link that
   * logs victim into attacker's account.
   */
  const state = crypto.randomBytes(32).toString('hex');

  /**
   * NONCE PARAMETER
   *
   * WHAT: Number used once
   * WHY: Prevents ID token replay attacks (OIDC specific)
   * HOW: We send it to Keycloak, it's included in the ID token,
   *      we verify it matches when validating the ID token.
   *
   * ATTACK PREVENTED:
   * Without nonce, attacker could replay an old ID token.
   */
  const nonce = crypto.randomBytes(32).toString('hex');

  /**
   * PKCE PARAMETERS
   *
   * WHAT: code_verifier (secret) and code_challenge (hash)
   * WHY: Prevents authorization code interception attacks
   * HOW: We send hash with auth request, send secret when
   *      exchanging code, server verifies they match.
   */
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Store in session for verification in callback
  req.session.oauth = {
    state,
    nonce,
    codeVerifier,
    returnTo: req.query.returnTo || '/',
  };

  // --------------------------------------------------------
  // Build Authorization URL
  // --------------------------------------------------------

  /**
   * AUTHORIZATION REQUEST PARAMETERS
   *
   * REQUIRED:
   *   response_type: "code" for Authorization Code Flow
   *   client_id: Identifies our application
   *   redirect_uri: Where to send the authorization code
   *   scope: What access we're requesting
   *
   * SECURITY:
   *   state: CSRF protection
   *   nonce: Replay attack prevention (OIDC)
   *   code_challenge: PKCE challenge
   *   code_challenge_method: "S256" for SHA256
   */
  const authUrl = new URL(oauthConfig.authorizationEndpoint);

  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', oauthConfig.clientId);
  authUrl.searchParams.set('redirect_uri', oauthConfig.redirectUri);
  authUrl.searchParams.set('scope', oauthConfig.scopes.join(' '));
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  console.log('[AUTH] Initiating Authorization Code Flow');
  console.log('[AUTH] State:', state.substring(0, 16) + '...');
  console.log('[AUTH] Redirecting to:', authUrl.origin + authUrl.pathname);

  // Redirect user to Keycloak login page
  res.redirect(authUrl.toString());
});

/**
 * GET /auth/callback
 *
 * Handles the callback from Keycloak after user authentication.
 *
 * WHAT HAPPENS:
 * 1. Verify state parameter (CSRF protection)
 * 2. Check for error responses from Keycloak
 * 3. Exchange authorization code for tokens
 * 4. Validate ID token (signature, issuer, audience, nonce)
 * 5. Create authenticated session
 * 6. Redirect to original destination
 *
 * QUERY PARAMETERS (from Keycloak):
 *   code  - Authorization code to exchange for tokens
 *   state - Must match what we sent
 *   error - Present if authentication failed
 *   error_description - Details about the error
 */
router.get('/callback', async (req, res, next) => {
  try {
    const { code, state, error, error_description } = req.query;
    const storedOAuth = req.session.oauth;

    console.log('[CALLBACK] Received callback from authorization server');

    // --------------------------------------------------------
    // Step 1: Check for Error Response
    // --------------------------------------------------------
    /**
     * ERROR RESPONSES
     *
     * Keycloak returns errors when:
     * - User denied consent
     * - Invalid client_id or redirect_uri
     * - Server errors
     */
    if (error) {
      console.error('[CALLBACK] Authorization error:', error, error_description);
      throw new Error(`Authorization failed: ${error_description || error}`);
    }

    // --------------------------------------------------------
    // Step 2: Verify State (CSRF Protection)
    // --------------------------------------------------------
    /**
     * STATE VERIFICATION
     *
     * CRITICAL SECURITY CHECK:
     * If state doesn't match, this could be a CSRF attack.
     * An attacker may have crafted a malicious callback URL.
     */
    if (!storedOAuth) {
      console.error('[CALLBACK] No OAuth session data found');
      throw new Error('Invalid session - please try logging in again');
    }

    if (storedOAuth.state !== state) {
      console.error('[CALLBACK] State mismatch!');
      console.error('[CALLBACK] Expected:', storedOAuth.state.substring(0, 16) + '...');
      console.error('[CALLBACK] Received:', state?.substring(0, 16) + '...');
      throw new Error('Invalid state parameter - possible CSRF attack');
    }

    console.log('[CALLBACK] State verified successfully');

    // --------------------------------------------------------
    // Step 3: Verify Authorization Code Present
    // --------------------------------------------------------
    if (!code) {
      throw new Error('No authorization code received');
    }

    console.log('[CALLBACK] Authorization code received, exchanging for tokens...');

    // --------------------------------------------------------
    // Step 4: Exchange Code for Tokens
    // --------------------------------------------------------
    /**
     * TOKEN EXCHANGE
     *
     * This is a server-to-server request (back-channel).
     * We send:
     *   - The authorization code
     *   - Our client credentials
     *   - The PKCE code_verifier
     *
     * We receive:
     *   - access_token: For accessing protected resources
     *   - id_token: Contains user identity (JWT)
     *   - refresh_token: For getting new access tokens
     *   - expires_in: Token lifetime in seconds
     */
    const tokens = await tokenService.exchangeCodeForTokens(
      code,
      storedOAuth.codeVerifier
    );

    console.log('[CALLBACK] Tokens received successfully');

    // --------------------------------------------------------
    // Step 5: Validate ID Token
    // --------------------------------------------------------
    /**
     * ID TOKEN VALIDATION
     *
     * CRITICAL: Never trust an ID token without validation!
     *
     * We verify:
     *   - Signature using Keycloak's public key (JWKS)
     *   - Issuer matches expected value
     *   - Audience contains our client_id
     *   - Token is not expired
     *   - Nonce matches what we sent
     */
    const idTokenClaims = await tokenService.validateIdToken(
      tokens.id_token,
      storedOAuth.nonce
    );

    console.log('[CALLBACK] ID token validated for user:', idTokenClaims.sub);

    // --------------------------------------------------------
    // Step 6: Create Authenticated Session
    // --------------------------------------------------------
    /**
     * SESSION STORAGE
     *
     * We store:
     *   - Tokens: For API calls and refresh
     *   - User info: For display and authorization decisions
     *   - Expiration: To know when to refresh
     */
    req.session.tokens = {
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + (tokens.expires_in * 1000),
    };

    req.session.user = {
      sub: idTokenClaims.sub,
      email: idTokenClaims.email,
      name: idTokenClaims.name || idTokenClaims.preferred_username,
      preferredUsername: idTokenClaims.preferred_username,
    };

    // Clean up OAuth session data (no longer needed)
    const returnTo = storedOAuth.returnTo || '/';
    delete req.session.oauth;

    console.log('[CALLBACK] Session created, redirecting to:', returnTo);

    // Redirect to original destination
    res.redirect(returnTo);

  } catch (error) {
    console.error('[CALLBACK] Error:', error.message);
    next(error);
  }
});

/**
 * GET /auth/logout
 *
 * Logs out the user from both the application and Keycloak.
 *
 * LOGOUT TYPES:
 *
 * 1. LOCAL LOGOUT (session.destroy only):
 *    - Clears our application session
 *    - User must re-login to our app
 *    - User remains logged into Keycloak (SSO)
 *
 * 2. RP-INITIATED LOGOUT (we implement this):
 *    - Clears our application session
 *    - Also ends Keycloak SSO session
 *    - User must re-authenticate everywhere
 *
 * QUERY PARAMETERS:
 *   id_token_hint - Helps Keycloak identify the session
 *   post_logout_redirect_uri - Where to redirect after logout
 */
router.get('/logout', (req, res) => {
  console.log('[LOGOUT] Initiating logout');

  // Get ID token for Keycloak logout (optional but recommended)
  const idToken = req.session.tokens?.idToken;

  // Clear local session
  req.session.destroy((err) => {
    if (err) {
      console.error('[LOGOUT] Session destruction error:', err);
    }
  });

  // Build Keycloak logout URL
  const logoutUrl = new URL(oauthConfig.endSessionEndpoint);
  logoutUrl.searchParams.set('post_logout_redirect_uri', oauthConfig.postLogoutRedirectUri);

  /**
   * ID TOKEN HINT
   *
   * Sending the ID token helps Keycloak:
   * - Identify which user is logging out
   * - Skip the "Do you want to logout?" confirmation
   * - Properly end the correct session
   */
  if (idToken) {
    logoutUrl.searchParams.set('id_token_hint', idToken);
  }

  console.log('[LOGOUT] Redirecting to Keycloak logout');

  // Redirect to Keycloak logout
  res.redirect(logoutUrl.toString());
});

module.exports = router;

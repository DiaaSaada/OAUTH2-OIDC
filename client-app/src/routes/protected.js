/**
 * ============================================================
 * PROTECTED ROUTES
 * ============================================================
 *
 * These routes demonstrate how to protect resources using OAuth2.
 * Only authenticated users can access these endpoints.
 *
 * PROTECTION METHODS:
 *
 * 1. SESSION-BASED (used here):
 *    Check if user session exists
 *    Simple for server-rendered apps
 *
 * 2. TOKEN-BASED:
 *    Validate access token on each request
 *    Used for API protection (see resource-server)
 *
 * ============================================================
 */

const express = require('express');
const router = express.Router();

const tokenService = require('../services/tokenService');

/**
 * AUTHENTICATION MIDDLEWARE
 *
 * Ensures user is authenticated before accessing protected routes.
 * If not authenticated, redirects to login with return URL.
 */
function requireAuth(req, res, next) {
  if (!req.session.user) {
    console.log('[PROTECTED] Access denied - user not authenticated');
    // Store intended destination for redirect after login
    return res.redirect(`/auth/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
  }
  next();
}

// Apply auth middleware to all routes in this router
router.use(requireAuth);

/**
 * GET /protected/profile
 *
 * Displays user profile information.
 *
 * EDUCATIONAL NOTE:
 * User info comes from two sources:
 * 1. ID Token claims (stored in session at login)
 * 2. UserInfo endpoint (fetched on demand)
 *
 * The UserInfo endpoint returns current data, while
 * ID token claims are frozen at authentication time.
 */
router.get('/profile', async (req, res, next) => {
  try {
    console.log('[PROTECTED] Rendering profile page');

    // Optionally fetch fresh user info from UserInfo endpoint
    let freshUserInfo = null;
    try {
      freshUserInfo = await tokenService.getUserInfo(req.session.tokens.accessToken);
    } catch (error) {
      console.log('[PROTECTED] Could not fetch fresh user info:', error.message);
    }

    res.render('profile', {
      title: 'User Profile',
      sessionUser: req.session.user,
      freshUserInfo: freshUserInfo,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /protected/tokens
 *
 * Displays token information for educational purposes.
 *
 * WARNING: In a real application, you would NEVER expose
 * tokens to the user interface. This is purely for learning!
 *
 * DISPLAYED INFORMATION:
 * - Access token structure (header, payload, signature)
 * - ID token structure and claims
 * - Token expiration times
 * - Explanations of each claim
 */
router.get('/tokens', (req, res) => {
  console.log('[PROTECTED] Rendering tokens page');

  const tokens = req.session.tokens;

  // Parse tokens for display
  const accessTokenParsed = tokenService.parseJwtForDisplay(tokens.accessToken);
  const idTokenParsed = tokenService.parseJwtForDisplay(tokens.idToken);

  res.render('tokens', {
    title: 'Token Inspector',
    tokens: tokens,
    accessTokenParsed: accessTokenParsed,
    idTokenParsed: idTokenParsed,
  });
});

/**
 * GET /protected/api-demo
 *
 * Demonstrates how to call a protected API using the access token.
 *
 * In a real application, you would:
 * 1. Check if access token is expired
 * 2. Refresh if needed
 * 3. Make API call with Bearer token
 * 4. Handle 401 errors (token rejected)
 */
router.get('/api-demo', async (req, res, next) => {
  try {
    console.log('[PROTECTED] Rendering API demo page');

    const tokens = req.session.tokens;
    const isExpired = Date.now() > tokens.expiresAt;
    const timeRemaining = Math.max(0, Math.floor((tokens.expiresAt - Date.now()) / 1000));

    res.render('api-demo', {
      title: 'API Demo',
      accessToken: tokens.accessToken,
      isExpired: isExpired,
      timeRemaining: timeRemaining,
      expiresAt: new Date(tokens.expiresAt).toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /protected/refresh
 *
 * Manually triggers a token refresh.
 * Demonstrates how refresh tokens work.
 */
router.post('/refresh', async (req, res, next) => {
  try {
    console.log('[PROTECTED] Manual token refresh requested');

    const refreshToken = req.session.tokens.refreshToken;
    const newTokens = await tokenService.refreshTokens(refreshToken);

    // Update session with new tokens
    req.session.tokens = {
      accessToken: newTokens.access_token,
      idToken: newTokens.id_token || req.session.tokens.idToken,
      refreshToken: newTokens.refresh_token || refreshToken,
      expiresAt: Date.now() + (newTokens.expires_in * 1000),
    };

    console.log('[PROTECTED] Tokens refreshed successfully');

    res.redirect('/protected/tokens');
  } catch (error) {
    console.error('[PROTECTED] Refresh failed:', error.message);
    next(error);
  }
});

module.exports = router;

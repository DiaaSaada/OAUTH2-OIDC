/**
 * ============================================================
 * API ROUTES
 * ============================================================
 *
 * Demonstrates different levels of API protection:
 *
 * PUBLIC ENDPOINTS:
 * - No authentication required
 * - Anyone can access
 *
 * PROTECTED ENDPOINTS:
 * - Require valid access token
 * - Any authenticated user can access
 *
 * SCOPE-PROTECTED ENDPOINTS:
 * - Require valid access token
 * - Require specific scopes (permissions)
 *
 * ============================================================
 */

const express = require('express');
const router = express.Router();

const validateToken = require('../middleware/validateToken');

// ============================================================
// PUBLIC ENDPOINTS
// ============================================================

/**
 * GET /api/public
 *
 * A public endpoint that doesn't require authentication.
 * Useful for health checks, public data, etc.
 */
router.get('/public', (req, res) => {
  console.log('[API] Public endpoint accessed');

  res.json({
    message: 'This is a public endpoint - no authentication required',
    timestamp: new Date().toISOString(),
    tip: 'Try calling /api/protected with a Bearer token',
  });
});

/**
 * GET /api/info
 *
 * Returns information about the API and its endpoints.
 */
router.get('/info', (req, res) => {
  res.json({
    name: 'OAuth2/OIDC Learning API',
    version: '1.0.0',
    endpoints: {
      '/api/public': 'Public - no auth required',
      '/api/protected': 'Protected - requires valid token',
      '/api/me': 'Protected - returns user info from token',
      '/api/scoped': 'Protected - requires api:read scope',
    },
    documentation: 'See /docs folder in the project',
  });
});

// ============================================================
// PROTECTED ENDPOINTS
// ============================================================

/**
 * GET /api/protected
 *
 * A protected endpoint that requires a valid access token.
 * Any authenticated user can access this endpoint.
 *
 * EDUCATIONAL NOTE:
 * The validateToken() middleware:
 * 1. Extracts the Bearer token from Authorization header
 * 2. Validates the JWT signature
 * 3. Checks expiration and issuer
 * 4. Attaches claims to req.auth
 */
router.get('/protected', validateToken(), (req, res) => {
  console.log('[API] Protected endpoint accessed by:', req.auth.userId);

  res.json({
    message: 'You have accessed a protected resource!',
    user: {
      id: req.auth.userId,
      username: req.auth.username,
      email: req.auth.email,
    },
    tokenInfo: {
      scopes: req.auth.scopes,
      issuedBy: req.auth.claims.iss,
    },
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/me
 *
 * Returns information about the authenticated user.
 * Extracts user details from the access token claims.
 *
 * EDUCATIONAL NOTE:
 * This is similar to the UserInfo endpoint, but:
 * - UserInfo: Fetched from authorization server
 * - /api/me: Extracted from access token
 *
 * Access token claims might be a subset of UserInfo.
 */
router.get('/me', validateToken(), (req, res) => {
  console.log('[API] User info requested by:', req.auth.userId);

  // Extract user claims from the token
  const { claims } = req.auth;

  res.json({
    sub: claims.sub,
    preferred_username: claims.preferred_username,
    name: claims.name,
    given_name: claims.given_name,
    family_name: claims.family_name,
    email: claims.email,
    email_verified: claims.email_verified,
    // Token metadata
    token_issued_at: new Date(claims.iat * 1000).toISOString(),
    token_expires_at: new Date(claims.exp * 1000).toISOString(),
  });
});

/**
 * GET /api/scoped
 *
 * A protected endpoint that requires specific scopes.
 * Demonstrates scope-based authorization.
 *
 * EDUCATIONAL NOTE - Scopes:
 * Scopes are permissions granted to the access token.
 * They control what the token can do.
 *
 * To test this endpoint:
 * 1. Configure 'api:read' scope in Keycloak
 * 2. Add scope to client's default scopes
 * 3. Include scope in authorization request
 */
router.get('/scoped', validateToken({ requiredScopes: ['api:read'] }), (req, res) => {
  console.log('[API] Scoped endpoint accessed by:', req.auth.userId);
  console.log('[API] User scopes:', req.auth.scopes);

  res.json({
    message: 'You have access to this scope-protected resource!',
    requiredScope: 'api:read',
    yourScopes: req.auth.scopes,
    user: req.auth.userId,
  });
});

// ============================================================
// EXAMPLE PROTECTED RESOURCES
// ============================================================

/**
 * GET /api/data
 *
 * Example of a protected data endpoint.
 * In a real app, this would return actual data from a database.
 */
router.get('/data', validateToken(), (req, res) => {
  console.log('[API] Data requested by:', req.auth.userId);

  // Simulated data - in reality, fetch from database
  const userData = {
    items: [
      { id: 1, name: 'Item 1', owner: req.auth.userId },
      { id: 2, name: 'Item 2', owner: req.auth.userId },
      { id: 3, name: 'Item 3', owner: req.auth.userId },
    ],
    total: 3,
    page: 1,
  };

  res.json({
    message: 'Here is your protected data',
    data: userData,
    accessedBy: req.auth.username,
  });
});

/**
 * POST /api/data
 *
 * Example of a protected write endpoint.
 * Could require a different scope (e.g., 'api:write').
 */
router.post('/data', validateToken(), (req, res) => {
  console.log('[API] Data creation by:', req.auth.userId);
  console.log('[API] Request body:', req.body);

  // In reality, save to database
  const created = {
    id: Date.now(),
    ...req.body,
    createdBy: req.auth.userId,
    createdAt: new Date().toISOString(),
  };

  res.status(201).json({
    message: 'Resource created successfully',
    data: created,
  });
});

// ============================================================
// ERROR DEMONSTRATION
// ============================================================

/**
 * GET /api/error-demo
 *
 * Demonstrates how the API handles errors.
 * Useful for testing error handling in clients.
 */
router.get('/error-demo', validateToken(), (req, res) => {
  const errorType = req.query.type || 'generic';

  switch (errorType) {
    case 'forbidden':
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: 'You do not have permission for this resource',
      });
    case 'notfound':
      return res.status(404).json({
        error: 'not_found',
        error_description: 'The requested resource does not exist',
      });
    default:
      return res.status(500).json({
        error: 'server_error',
        error_description: 'An internal server error occurred',
      });
  }
});

module.exports = router;

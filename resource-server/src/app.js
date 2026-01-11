/**
 * ============================================================
 * OAUTH2/OIDC LEARNING PROJECT - RESOURCE SERVER
 * ============================================================
 *
 * This Express application demonstrates how to protect APIs
 * using OAuth2 access tokens.
 *
 * WHAT IS A RESOURCE SERVER?
 *
 * In OAuth2 terminology, the Resource Server is the API that
 * hosts protected resources. It:
 * - Receives access tokens from clients
 * - Validates tokens before granting access
 * - Enforces scope-based authorization
 *
 * TOKEN VALIDATION APPROACHES:
 *
 * 1. LOCAL JWT VALIDATION (implemented here):
 *    - Decode JWT and verify signature using public keys
 *    - Fast - no network call needed
 *    - Cannot detect revoked tokens
 *
 * 2. TOKEN INTROSPECTION:
 *    - Call authorization server's introspection endpoint
 *    - Always current - knows if token is revoked
 *    - Slower - requires network call
 *
 * ============================================================
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');

const validateToken = require('./middleware/validateToken');
const apiRoutes = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 3001;

// ============================================================
// MIDDLEWARE
// ============================================================

/**
 * CORS CONFIGURATION
 *
 * Cross-Origin Resource Sharing (CORS) headers allow
 * the client app (running on a different port) to call our API.
 *
 * In production, you would restrict this to specific origins.
 */
app.use(cors({
  origin: 'http://localhost:3000', // Client app origin
  credentials: true,
}));

// Parse JSON request bodies
app.use(express.json());

/**
 * REQUEST LOGGING
 *
 * Log all incoming requests for educational purposes.
 * Shows the Authorization header (truncated for security).
 */
app.use((req, res, next) => {
  const auth = req.headers.authorization;
  const authInfo = auth
    ? `Bearer ${auth.substring(7, 27)}...`
    : 'None';

  console.log(`[API] ${req.method} ${req.path} | Auth: ${authInfo}`);
  next();
});

// ============================================================
// ROUTES
// ============================================================

/**
 * API ROUTES
 *
 * /api/public - Accessible without authentication
 * /api/protected - Requires valid access token
 * /api/admin - Requires valid token + specific scope
 */
app.use('/api', apiRoutes);

/**
 * HEALTH CHECK
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'resource-server' });
});

// ============================================================
// ERROR HANDLING
// ============================================================

/**
 * 404 HANDLER
 */
app.use((req, res) => {
  res.status(404).json({
    error: 'not_found',
    error_description: `Endpoint ${req.method} ${req.path} not found`,
  });
});

/**
 * ERROR HANDLER
 *
 * Returns errors in OAuth2-style format for consistency.
 */
app.use((err, req, res, next) => {
  console.error('[API] Error:', err.message);

  res.status(err.status || 500).json({
    error: err.code || 'server_error',
    error_description: err.message,
  });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, () => {
  console.log('');
  console.log('============================================================');
  console.log(' OAuth2/OIDC Learning Project - Resource Server');
  console.log('============================================================');
  console.log(`API running at: http://localhost:${PORT}`);
  console.log('');
  console.log('Available endpoints:');
  console.log(`  Public:    GET http://localhost:${PORT}/api/public`);
  console.log(`  Protected: GET http://localhost:${PORT}/api/protected`);
  console.log(`  User Info: GET http://localhost:${PORT}/api/me`);
  console.log(`  Health:    GET http://localhost:${PORT}/health`);
  console.log('');
  console.log('Token validation: Local JWT verification using JWKS');
  console.log('============================================================');
  console.log('');
});

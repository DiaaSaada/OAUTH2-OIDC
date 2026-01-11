/**
 * ============================================================
 * TOKEN VALIDATION MIDDLEWARE
 * ============================================================
 *
 * This middleware validates OAuth2 access tokens for API protection.
 *
 * VALIDATION PROCESS:
 *
 * 1. EXTRACT TOKEN
 *    Get Bearer token from Authorization header
 *
 * 2. DECODE JWT
 *    Parse header to get key ID (kid)
 *
 * 3. FETCH PUBLIC KEY
 *    Get signing key from Keycloak's JWKS endpoint
 *
 * 4. VERIFY SIGNATURE
 *    Ensure token was signed by Keycloak
 *
 * 5. CHECK CLAIMS
 *    Validate issuer, expiration, audience
 *
 * 6. CHECK SCOPES (optional)
 *    Verify token has required permissions
 *
 * SECURITY CONSIDERATIONS:
 *
 * - Always verify the signature
 * - Always check expiration
 * - Validate issuer to prevent cross-tenant attacks
 * - Check audience if token is meant for specific services
 * - Verify scopes for fine-grained authorization
 *
 * ============================================================
 */

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Configuration
const OAUTH_ISSUER = process.env.OAUTH_ISSUER || 'http://localhost:8080/realms/oauth2-learning';
const OAUTH_JWKS_URI = process.env.OAUTH_JWKS_URI ||
  'http://localhost:8080/realms/oauth2-learning/protocol/openid-connect/certs';

/**
 * JWKS CLIENT
 *
 * Fetches and caches public keys from Keycloak.
 *
 * EDUCATIONAL NOTE - JWKS (JSON Web Key Set):
 *
 * JWKS is a standard format for publishing public keys.
 * Keycloak exposes its signing keys at the /certs endpoint.
 *
 * Each key has:
 * - kid: Key ID (matches JWT header)
 * - kty: Key type (RSA, EC, etc.)
 * - n, e: RSA modulus and exponent
 * - use: Key usage (sig for signing)
 */
const jwks = jwksClient({
  jwksUri: OAUTH_JWKS_URI,
  cache: true,           // Cache keys for performance
  cacheMaxEntries: 5,    // Max keys to cache
  cacheMaxAge: 600000,   // Cache for 10 minutes
  rateLimit: true,       // Prevent excessive requests
  jwksRequestsPerMinute: 10,
});

/**
 * Token validation middleware factory.
 *
 * @param {Object} options - Validation options
 * @param {string[]} options.requiredScopes - Scopes required for access
 * @param {string} options.audience - Expected audience claim
 * @returns {Function} Express middleware
 *
 * @example
 * // Basic token validation
 * app.get('/api/data', validateToken(), handler);
 *
 * // With required scopes
 * app.get('/api/admin', validateToken({ requiredScopes: ['admin'] }), handler);
 */
function validateToken(options = {}) {
  return async (req, res, next) => {
    try {
      // --------------------------------------------------------
      // Step 1: Extract Token from Authorization Header
      // --------------------------------------------------------
      /**
       * BEARER TOKEN FORMAT
       *
       * Authorization: Bearer <token>
       *
       * The Bearer scheme indicates this is an OAuth2 access token.
       * Other schemes exist (Basic, Digest) but Bearer is standard for OAuth2.
       */
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        console.log('[VALIDATE] No Authorization header');
        return res.status(401).json({
          error: 'unauthorized',
          error_description: 'Missing Authorization header',
        });
      }

      if (!authHeader.startsWith('Bearer ')) {
        console.log('[VALIDATE] Invalid Authorization scheme');
        return res.status(401).json({
          error: 'unauthorized',
          error_description: 'Authorization header must use Bearer scheme',
        });
      }

      const token = authHeader.substring(7); // Remove "Bearer " prefix

      // --------------------------------------------------------
      // Step 2: Decode JWT Header
      // --------------------------------------------------------
      /**
       * JWT STRUCTURE
       *
       * A JWT has three parts: header.payload.signature
       * We decode the header to get the key ID (kid).
       */
      const decoded = jwt.decode(token, { complete: true });

      if (!decoded) {
        console.log('[VALIDATE] Could not decode token');
        return res.status(401).json({
          error: 'invalid_token',
          error_description: 'Token is not a valid JWT',
        });
      }

      const { kid } = decoded.header;

      if (!kid) {
        console.log('[VALIDATE] Token missing key ID');
        return res.status(401).json({
          error: 'invalid_token',
          error_description: 'Token missing key ID in header',
        });
      }

      // --------------------------------------------------------
      // Step 3: Fetch Public Key from JWKS
      // --------------------------------------------------------
      /**
       * KEY RETRIEVAL
       *
       * We use the kid from the token to fetch the correct public key.
       * Keys are cached to avoid fetching on every request.
       *
       * KEY ROTATION:
       * Authorization servers periodically rotate signing keys.
       * If a kid is not in cache, jwks-rsa fetches the latest keys.
       */
      let signingKey;
      try {
        const key = await jwks.getSigningKey(kid);
        signingKey = key.getPublicKey();
      } catch (error) {
        console.log('[VALIDATE] Could not fetch signing key:', error.message);
        return res.status(401).json({
          error: 'invalid_token',
          error_description: 'Could not verify token signature',
        });
      }

      // --------------------------------------------------------
      // Step 4 & 5: Verify Signature and Claims
      // --------------------------------------------------------
      /**
       * VERIFICATION
       *
       * jwt.verify() performs:
       * - Signature verification using public key
       * - Algorithm validation (must match what's in header)
       * - Expiration check (exp claim)
       * - Not-before check (nbf claim) if present
       * - Issuer validation (iss claim)
       */
      let claims;
      try {
        const verifyOptions = {
          algorithms: ['RS256'], // Keycloak uses RS256
          issuer: OAUTH_ISSUER,
        };

        // Add audience check if specified
        if (options.audience) {
          verifyOptions.audience = options.audience;
        }

        claims = jwt.verify(token, signingKey, verifyOptions);

      } catch (error) {
        console.log('[VALIDATE] Token verification failed:', error.message);

        // Provide specific error messages
        if (error.name === 'TokenExpiredError') {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Token has expired',
          });
        }

        if (error.name === 'JsonWebTokenError') {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: `Token invalid: ${error.message}`,
          });
        }

        throw error;
      }

      // --------------------------------------------------------
      // Step 6: Check Required Scopes
      // --------------------------------------------------------
      /**
       * SCOPE-BASED AUTHORIZATION
       *
       * Scopes define what the token is allowed to do.
       * The 'scope' claim contains space-separated scope names.
       *
       * Example: "openid profile email api:read"
       */
      if (options.requiredScopes && options.requiredScopes.length > 0) {
        const tokenScopes = (claims.scope || '').split(' ');

        const hasAllScopes = options.requiredScopes.every(
          requiredScope => tokenScopes.includes(requiredScope)
        );

        if (!hasAllScopes) {
          console.log('[VALIDATE] Insufficient scopes');
          console.log('[VALIDATE] Required:', options.requiredScopes);
          console.log('[VALIDATE] Has:', tokenScopes);

          return res.status(403).json({
            error: 'insufficient_scope',
            error_description: `Required scopes: ${options.requiredScopes.join(', ')}`,
            scope: options.requiredScopes.join(' '),
          });
        }
      }

      // --------------------------------------------------------
      // Success: Attach Claims to Request
      // --------------------------------------------------------
      /**
       * REQUEST ENRICHMENT
       *
       * We attach the validated claims to the request object
       * so route handlers can access user information.
       */
      req.auth = {
        token: token,
        claims: claims,
        userId: claims.sub,
        username: claims.preferred_username,
        email: claims.email,
        scopes: (claims.scope || '').split(' '),
      };

      console.log('[VALIDATE] Token valid for user:', claims.sub);

      next();

    } catch (error) {
      console.error('[VALIDATE] Unexpected error:', error);
      return res.status(500).json({
        error: 'server_error',
        error_description: 'Token validation failed',
      });
    }
  };
}

module.exports = validateToken;

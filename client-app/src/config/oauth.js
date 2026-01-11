/**
 * ============================================================
 * OAUTH2/OIDC CONFIGURATION
 * ============================================================
 *
 * EDUCATIONAL NOTE - Configuration Structure:
 *
 * This file centralizes all OAuth2/OIDC configuration.
 * In a real application, you might fetch this dynamically
 * from the discovery endpoint (.well-known/openid-configuration).
 *
 * For learning purposes, we configure endpoints manually to
 * understand what each one does.
 * ============================================================
 */

require('dotenv').config();

/**
 * EDUCATIONAL NOTE - Keycloak URL Structure:
 *
 * Keycloak organizes URLs by realm:
 *   Base: http://localhost:8080
 *   Realm: /realms/{realm-name}
 *   OIDC: /protocol/openid-connect/{endpoint}
 *
 * Example for realm "oauth2-learning":
 *   Token endpoint: http://localhost:8080/realms/oauth2-learning/protocol/openid-connect/token
 */

const issuer = process.env.OAUTH_ISSUER || 'http://localhost:8080/realms/oauth2-learning';

const oauthConfig = {
  // --------------------------------------------------------
  // Issuer (Authorization Server)
  // --------------------------------------------------------
  // The base URL of the OIDC provider. Used for:
  // - Building endpoint URLs
  // - Validating token issuer claims
  // --------------------------------------------------------
  issuer,

  // --------------------------------------------------------
  // Client Credentials
  // --------------------------------------------------------
  // EDUCATIONAL NOTE:
  // client_id: Public identifier for your app
  // client_secret: Confidential key (never expose in frontend!)
  //
  // In Keycloak: Clients > your-client > Credentials tab
  // --------------------------------------------------------
  clientId: process.env.OAUTH_CLIENT_ID || 'express-client',
  clientSecret: process.env.OAUTH_CLIENT_SECRET,

  // --------------------------------------------------------
  // Redirect URIs
  // --------------------------------------------------------
  // EDUCATIONAL NOTE:
  // These MUST exactly match what's configured in Keycloak.
  // Even a trailing slash difference will cause errors!
  //
  // redirect_uri: Where Keycloak sends the authorization code
  // post_logout_redirect_uri: Where to go after logout
  // --------------------------------------------------------
  redirectUri: process.env.OAUTH_REDIRECT_URI || 'http://localhost:3000/auth/callback',
  postLogoutRedirectUri: process.env.OAUTH_POST_LOGOUT_REDIRECT_URI || 'http://localhost:3000',

  // --------------------------------------------------------
  // Scopes
  // --------------------------------------------------------
  // EDUCATIONAL NOTE - Standard OIDC Scopes:
  //
  // openid   - Required for OIDC. Returns sub claim & ID token
  // profile  - Returns name, family_name, given_name, etc.
  // email    - Returns email and email_verified
  // phone    - Returns phone_number and phone_number_verified
  // address  - Returns address object
  // --------------------------------------------------------
  scopes: (process.env.OAUTH_SCOPES || 'openid profile email').split(' '),

  // --------------------------------------------------------
  // OAuth2/OIDC Endpoints
  // --------------------------------------------------------
  // EDUCATIONAL NOTE - What each endpoint does:
  //
  // authorization: User login and consent (browser redirect)
  // token: Exchange code for tokens (server-to-server)
  // userinfo: Get user profile (using access token)
  // jwks: Public keys for JWT verification
  // endSession: Logout endpoint
  // introspection: Check if token is valid/active
  // --------------------------------------------------------
  authorizationEndpoint: `${issuer}/protocol/openid-connect/auth`,
  tokenEndpoint: `${issuer}/protocol/openid-connect/token`,
  userInfoEndpoint: `${issuer}/protocol/openid-connect/userinfo`,
  jwksUri: `${issuer}/protocol/openid-connect/certs`,
  endSessionEndpoint: `${issuer}/protocol/openid-connect/logout`,
  introspectionEndpoint: `${issuer}/protocol/openid-connect/token/introspect`,
};

// Validate required configuration
if (!oauthConfig.clientSecret) {
  console.warn('WARNING: OAUTH_CLIENT_SECRET not set. Token exchange will fail.');
}

module.exports = { oauthConfig };

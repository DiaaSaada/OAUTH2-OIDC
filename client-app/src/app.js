/**
 * ============================================================
 * OAUTH2/OIDC LEARNING PROJECT - CLIENT APPLICATION
 * ============================================================
 *
 * This Express application demonstrates OAuth2 Authorization Code
 * Flow with PKCE, integrated with Keycloak as the Authorization Server.
 *
 * ARCHITECTURE OVERVIEW:
 *
 *   Browser ──► Express App (this) ──► Keycloak
 *                    │                     │
 *                    │ 1. /auth/login      │
 *                    │────────────────────►│
 *                    │                     │ 2. User authenticates
 *                    │ 3. Callback + code  │
 *                    │◄────────────────────│
 *                    │ 4. Exchange code    │
 *                    │────────────────────►│
 *                    │ 5. Tokens           │
 *                    │◄────────────────────│
 *
 * ============================================================
 */

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');

// Routes
const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// VIEW ENGINE SETUP
// ============================================================
// Using EJS for simple server-rendered HTML pages.
// In production, you might use React, Vue, or another framework.
// ============================================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ============================================================
// MIDDLEWARE
// ============================================================

// Parse form data
app.use(express.urlencoded({ extended: true }));

// Serve static files (CSS, etc.)
app.use(express.static(path.join(__dirname, 'public')));

/**
 * SESSION MIDDLEWARE
 *
 * EDUCATIONAL NOTE - Why sessions are important for OAuth2:
 *
 * 1. Store PKCE code_verifier between authorization and callback
 * 2. Store state parameter for CSRF protection
 * 3. Store nonce for ID token validation
 * 4. Store tokens after successful authentication
 *
 * SECURITY CONSIDERATIONS:
 * - Use secure: true in production (HTTPS only)
 * - Use a proper session store (Redis, etc.) in production
 * - The default MemoryStore is NOT suitable for production
 */
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevents JavaScript access
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));

/**
 * TEMPLATE LOCALS MIDDLEWARE
 *
 * Makes user info and auth status available in all templates.
 */
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.isAuthenticated = !!req.session.user;
  next();
});

// ============================================================
// ROUTES
// ============================================================

/**
 * HOME PAGE
 *
 * Displays authentication status and navigation options.
 */
app.get('/', (req, res) => {
  res.render('home', {
    title: 'OAuth2/OIDC Learning Project',
  });
});

/**
 * AUTH ROUTES
 *
 * /auth/login    - Initiates OAuth2 Authorization Code Flow
 * /auth/callback - Handles authorization server callback
 * /auth/logout   - Logs out user and ends Keycloak session
 */
app.use('/auth', authRoutes);

/**
 * PROTECTED ROUTES
 *
 * Routes that require authentication.
 * Demonstrates how to protect resources with OAuth2.
 */
app.use('/protected', protectedRoutes);

// ============================================================
// ERROR HANDLING
// ============================================================

/**
 * ERROR HANDLER
 *
 * Catches all errors and displays a user-friendly error page.
 * In development, shows detailed error information.
 */
app.use((err, req, res, next) => {
  console.error('Application error:', err);

  res.status(err.status || 500).render('error', {
    title: 'Error',
    message: err.message,
    error: process.env.NODE_ENV === 'development' ? err : {},
  });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, () => {
  console.log('');
  console.log('============================================================');
  console.log(' OAuth2/OIDC Learning Project - Client Application');
  console.log('============================================================');
  console.log(`Server running at: http://localhost:${PORT}`);
  console.log('');
  console.log('Available routes:');
  console.log(`  Home:       http://localhost:${PORT}/`);
  console.log(`  Login:      http://localhost:${PORT}/auth/login`);
  console.log(`  Callback:   http://localhost:${PORT}/auth/callback`);
  console.log(`  Logout:     http://localhost:${PORT}/auth/logout`);
  console.log(`  Profile:    http://localhost:${PORT}/protected/profile`);
  console.log(`  Tokens:     http://localhost:${PORT}/protected/tokens`);
  console.log('');
  console.log('Make sure Keycloak is running at: http://localhost:8080');
  console.log('============================================================');
  console.log('');
});

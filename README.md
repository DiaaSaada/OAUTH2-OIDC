# OAuth2 & OpenID Connect Learning Project

A hands-on learning project for understanding OAuth2 and OpenID Connect (OIDC) by building a complete authentication system with Keycloak.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│     Browser     │────▶│   Client App    │────▶│ Resource Server │
│     (User)      │     │  (Express:3000) │     │   (API:3001)    │
└─────────────────┘     └────────┬────────┘     └────────┬────────┘
                                 │                       │
                                 ▼                       ▼
                        ┌─────────────────────────────────────┐
                        │         Keycloak (Docker:8080)      │
                        │         Authorization Server        │
                        └─────────────────────────────────────┘
```

## What You'll Learn

- **Authorization Code Flow** with PKCE
- **Token Types**: Access Tokens, ID Tokens, Refresh Tokens
- **JWT Structure** and validation
- **Protecting APIs** with Bearer tokens
- **Scopes and Claims** for fine-grained authorization
- **Single Sign-On (SSO)** and logout

## Prerequisites

- Node.js 18+
- Docker and Docker Compose
- Basic JavaScript knowledge

## Quick Start

### 1. Start Keycloak

```bash
cd docker
docker-compose up -d
```

Wait 60 seconds for Keycloak to start, then access the admin console:
- URL: http://localhost:8080
- Username: `admin`
- Password: `admin`

### 2. Configure Keycloak

Follow the guide in `docs/03-keycloak-setup.md` or use these quick steps:

1. Create realm: `oauth2-learning`
2. Create client: `express-client`
   - Client authentication: ON
   - Valid redirect URIs: `http://localhost:3000/auth/callback`
   - Web origins: `http://localhost:3000`
3. Copy the client secret from Credentials tab
4. Create a test user with username/password

### 3. Configure Client App

```bash
cd client-app
cp .env.example .env
```

Edit `.env` and add your client secret:
```
OAUTH_CLIENT_SECRET=your-secret-from-keycloak
```

### 4. Start the Applications

```bash
# Terminal 1: Client App
cd client-app
npm install
npm start

# Terminal 2: Resource Server
cd resource-server
npm install
npm start
```

### 5. Test the Flow

1. Open http://localhost:3000
2. Click "Login with Keycloak"
3. Authenticate with your test user
4. Explore the protected pages:
   - Profile - View user information
   - Token Inspector - Examine your tokens
   - API Demo - Test protected API calls

## Project Structure

```
OAUTH2-OIDC/
├── docker/
│   └── docker-compose.yml      # Keycloak + PostgreSQL
├── client-app/                 # Express web application
│   └── src/
│       ├── app.js              # Main application
│       ├── routes/auth.js      # OAuth2 flow routes
│       ├── services/tokenService.js  # Token handling
│       └── utils/pkce.js       # PKCE utilities
├── resource-server/            # Protected API
│   └── src/
│       ├── app.js              # API server
│       ├── middleware/validateToken.js  # JWT validation
│       └── routes/api.js       # API endpoints
└── docs/                       # Learning documentation
    ├── 01-oauth2-basics.md
    ├── 02-oidc-explained.md
    └── 03-keycloak-setup.md
```

## Documentation

Read the docs in order for a complete learning experience:

1. **[OAuth2 Basics](docs/01-oauth2-basics.md)** - Roles, flows, and tokens
2. **[OIDC Explained](docs/02-oidc-explained.md)** - How OIDC extends OAuth2
3. **[Keycloak Setup](docs/03-keycloak-setup.md)** - Configuration guide

## Key Concepts

### Authorization Code Flow

```
1. User clicks Login
2. App redirects to Keycloak with:
   - client_id, redirect_uri, scope
   - state (CSRF protection)
   - code_challenge (PKCE)
3. User authenticates with Keycloak
4. Keycloak redirects back with authorization code
5. App exchanges code for tokens (back-channel)
6. App validates ID token and creates session
```

### Token Types

| Token | Purpose | Lifetime | Format |
|-------|---------|----------|--------|
| Access Token | API authorization | Short (5-15 min) | JWT or opaque |
| ID Token | User identity | Short | Always JWT |
| Refresh Token | Get new access tokens | Long (hours-days) | Opaque |

### Security Features

- **PKCE**: Prevents code interception attacks
- **State**: Prevents CSRF attacks
- **Nonce**: Prevents ID token replay attacks
- **JWKS**: Secure key distribution for JWT validation

## API Endpoints

### Client App (port 3000)

| Endpoint | Description |
|----------|-------------|
| `GET /` | Home page |
| `GET /auth/login` | Initiate OAuth2 flow |
| `GET /auth/callback` | Handle Keycloak callback |
| `GET /auth/logout` | End session |
| `GET /protected/profile` | User profile |
| `GET /protected/tokens` | Token inspector |

### Resource Server (port 3001)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/public` | None | Public endpoint |
| `GET /api/protected` | Bearer | Protected endpoint |
| `GET /api/me` | Bearer | User info from token |
| `GET /api/data` | Bearer | Example data endpoint |

## Troubleshooting

### "Invalid redirect URI" error
- Ensure redirect URI in Keycloak exactly matches `.env`
- Check for trailing slashes

### CORS errors
- Add `http://localhost:3000` to Web Origins in Keycloak client settings

### Token validation fails
- Ensure Keycloak is running and accessible
- Check issuer URL matches in all `.env` files

### Session errors
- Clear browser cookies
- Restart the client app

## Learn More

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [Keycloak Documentation](https://www.keycloak.org/documentation)

# OAuth 2.0 Basics

## What is OAuth 2.0?

OAuth 2.0 is an **authorization framework** that enables applications to obtain limited access to user accounts on third-party services. It works by delegating user authentication to the service that hosts the user account and authorizing third-party applications to access that account.

**Key Point:** OAuth 2.0 is about **authorization** (what you can do), not **authentication** (who you are).

---

## The Four Roles

OAuth 2.0 defines four distinct roles:

### 1. Resource Owner
The user who owns the data and can grant access to it.

**Example:** You, the person who has a Google account with photos stored in Google Drive.

### 2. Client
The application requesting access to the resource owner's data.

**Example:** A photo printing app that wants to access your Google Drive photos.

### 3. Authorization Server
The server that authenticates the resource owner and issues access tokens.

**Example:** Google's OAuth server that shows the login page and consent screen.

### 4. Resource Server
The server hosting the protected resources (APIs).

**Example:** Google Drive API that serves your photos.

```
┌──────────────────┐                          ┌──────────────────┐
│  Resource Owner  │                          │  Resource Server │
│     (User)       │                          │     (API)        │
└────────┬─────────┘                          └────────▲─────────┘
         │                                             │
         │ 1. Grants permission                        │ 4. Returns
         │                                             │    resources
         ▼                                             │
┌──────────────────┐      2. Auth code        ┌───────┴──────────┐
│     Client       │◄─────────────────────────│  Authorization   │
│  (Application)   │      3. Access token     │     Server       │
└──────────────────┘─────────────────────────►│   (Keycloak)     │
                                              └──────────────────┘
```

---

## OAuth 2.0 Grant Types (Flows)

OAuth 2.0 defines several "flows" for obtaining tokens, each suited for different scenarios:

### 1. Authorization Code Flow (Recommended for Web Apps)
**Best for:** Server-side web applications

```
User ──► Client ──► Authorization Server ──► User Login
                                           ──► Consent Screen
                            Auth Code ◄────────┘
Client ──► Auth Server (code + secret) ──► Access Token
```

**Why use it:**
- Most secure flow for web applications
- Tokens never exposed in browser
- Supports refresh tokens

### 2. Authorization Code Flow with PKCE
**Best for:** Mobile apps, Single Page Apps (SPAs)

Same as above, but adds PKCE (Proof Key for Code Exchange) for public clients that can't securely store a client secret.

### 3. Client Credentials Flow
**Best for:** Machine-to-machine communication

```
Client ──► Auth Server (client_id + secret) ──► Access Token
```

**Why use it:**
- No user involvement
- For backend services calling APIs
- Simple and direct

### 4. Resource Owner Password Flow (Deprecated)
**Avoid:** User provides password directly to the client application.

---

## Tokens Explained

### Access Token
- **Purpose:** Grants access to protected resources
- **Lifetime:** Short (minutes to hours)
- **Format:** Can be opaque string or JWT
- **Usage:** Sent in `Authorization: Bearer <token>` header

### Refresh Token
- **Purpose:** Obtain new access tokens without re-authentication
- **Lifetime:** Long (hours to days)
- **Storage:** Must be stored securely (server-side)
- **Usage:** Exchanged at token endpoint for new access token

---

## Key Endpoints

Authorization servers expose these standard endpoints:

| Endpoint | Purpose |
|----------|---------|
| `/authorize` | User authentication and consent |
| `/token` | Exchange code for tokens, refresh tokens |
| `/introspect` | Validate token status (RFC 7662) |
| `/revoke` | Revoke tokens (RFC 7009) |
| `/.well-known/openid-configuration` | Discovery document (OIDC) |

---

## Scopes

Scopes define the permissions being requested:

```
scope=read:photos write:albums
```

Common patterns:
- `read`, `write`, `delete` - CRUD operations
- `profile`, `email`, `phone` - User data (OIDC)
- `openid` - Required for OIDC (enables ID token)

---

## Security Parameters

### State
Random value to prevent CSRF attacks.
```
1. Client generates: state=abc123
2. Sends to auth server
3. Auth server returns same state in callback
4. Client verifies state matches
```

### Code Challenge (PKCE)
Prevents authorization code interception:
```
1. Client generates: code_verifier (random string)
2. Client creates: code_challenge = SHA256(code_verifier)
3. Sends code_challenge to auth server
4. Later sends code_verifier when exchanging code
5. Server verifies: SHA256(code_verifier) === stored challenge
```

---

## Common Pitfalls

1. **Storing tokens in localStorage** - Vulnerable to XSS attacks
2. **Not validating state** - Opens CSRF vulnerabilities
3. **Long-lived access tokens** - Increases attack window
4. **Skipping PKCE** - Even confidential clients should use it
5. **Exposing client secrets** - Never in frontend code

---

## Next Steps

Now that you understand OAuth 2.0 basics, learn how OIDC extends it for authentication in [02-oidc-explained.md](./02-oidc-explained.md).

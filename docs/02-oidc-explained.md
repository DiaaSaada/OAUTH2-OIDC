# OpenID Connect (OIDC) Explained

## What is OpenID Connect?

OpenID Connect (OIDC) is an **identity layer** built on top of OAuth 2.0. While OAuth 2.0 handles authorization (access to resources), OIDC adds **authentication** (proving who the user is).

```
┌─────────────────────────────────────────────┐
│            OpenID Connect (OIDC)            │
│         Authentication / Identity           │
├─────────────────────────────────────────────┤
│              OAuth 2.0                      │
│         Authorization / Access              │
└─────────────────────────────────────────────┘
```

**Simple analogy:**
- OAuth 2.0 = Hotel key card (grants access to specific rooms)
- OIDC = Hotel key card + Guest ID (proves who you are AND grants access)

---

## Key Additions Over OAuth 2.0

### 1. ID Token
A new token type that contains user identity claims.

```json
{
  "iss": "https://keycloak.example.com/realms/myrealm",
  "sub": "user-123",
  "aud": "my-client-id",
  "exp": 1699900000,
  "iat": 1699896400,
  "nonce": "abc123",
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true
}
```

**Key differences from Access Token:**
| ID Token | Access Token |
|----------|--------------|
| For the client | For the resource server |
| Contains user identity | Contains permissions/scopes |
| Always a JWT | Can be opaque or JWT |
| Must be validated | Validated by resource server |

### 2. UserInfo Endpoint
API endpoint to fetch user profile information.

```
GET /userinfo
Authorization: Bearer <access_token>

Response:
{
  "sub": "user-123",
  "name": "John Doe",
  "email": "john@example.com"
}
```

### 3. Standard Scopes
OIDC defines standard scopes for user data:

| Scope | Claims Returned |
|-------|-----------------|
| `openid` | Required. Enables OIDC (returns `sub`) |
| `profile` | `name`, `family_name`, `given_name`, `picture`, etc. |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `address` | `address` (structured object) |

### 4. Discovery Document
Standard endpoint for auto-configuration:

```
GET /.well-known/openid-configuration

Response:
{
  "issuer": "https://keycloak.example.com/realms/myrealm",
  "authorization_endpoint": "https://.../auth",
  "token_endpoint": "https://.../token",
  "userinfo_endpoint": "https://.../userinfo",
  "jwks_uri": "https://.../certs",
  ...
}
```

---

## The ID Token in Detail

### JWT Structure
ID tokens are always JWTs (JSON Web Tokens) with three parts:

```
header.payload.signature
```

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-123"
}
```

**Payload (Claims):**
```json
{
  "iss": "https://keycloak.example.com/realms/myrealm",
  "sub": "user-123",
  "aud": "my-client-id",
  "exp": 1699900000,
  "iat": 1699896400,
  "auth_time": 1699896400,
  "nonce": "random-nonce",
  "name": "John Doe",
  "preferred_username": "johnd",
  "email": "john@example.com"
}
```

### Required Claims

| Claim | Description |
|-------|-------------|
| `iss` | Issuer - Who issued the token |
| `sub` | Subject - Unique user identifier |
| `aud` | Audience - Who the token is intended for |
| `exp` | Expiration - When the token expires |
| `iat` | Issued At - When the token was created |

### ID Token Validation Checklist

You **MUST** validate ID tokens before trusting them:

1. **Signature** - Verify using issuer's public key (JWKS)
2. **Issuer (iss)** - Must match expected issuer URL
3. **Audience (aud)** - Must contain your client_id
4. **Expiration (exp)** - Must be in the future
5. **Issued At (iat)** - Should not be too far in the past
6. **Nonce** - Must match the nonce you sent in auth request

---

## Nonce: Preventing Replay Attacks

The `nonce` (number used once) prevents replay attacks:

```
1. Client generates: nonce = "random-xyz"
2. Client stores nonce in session
3. Client sends nonce in authorization request
4. Auth server includes nonce in ID token
5. Client verifies: id_token.nonce === stored nonce
```

**Why it matters:** Without nonce validation, an attacker could replay an old ID token to impersonate a user.

---

## OIDC Flows

OIDC supports several response types:

### Authorization Code Flow (`response_type=code`)
**Recommended for most applications**

1. Get authorization code
2. Exchange code for tokens (including ID token)
3. Validate ID token
4. Use access token for API calls

### Implicit Flow (`response_type=id_token token`)
**Deprecated** - Tokens exposed in browser URL

### Hybrid Flow (`response_type=code id_token`)
Get ID token immediately, exchange code for access token later.

---

## Logout in OIDC

### RP-Initiated Logout
The Relying Party (client) initiates logout:

```
GET /logout?
  id_token_hint=<id_token>&
  post_logout_redirect_uri=https://myapp.com/logged-out
```

The Authorization Server:
1. Ends the SSO session
2. Redirects to post_logout_redirect_uri
3. Optionally notifies other clients (back-channel logout)

---

## OIDC vs OAuth 2.0 Summary

| Feature | OAuth 2.0 | OIDC |
|---------|-----------|------|
| Purpose | Authorization | Authentication + Authorization |
| User Identity | Not provided | ID Token with claims |
| User Info | No standard | UserInfo endpoint |
| Token Format | No requirement | ID Token must be JWT |
| Scopes | Application-defined | Standard scopes (openid, profile, etc.) |
| Discovery | No standard | .well-known/openid-configuration |

---

## Common Keycloak Endpoints

For a Keycloak realm named `oauth2-learning`:

```
Base URL: http://localhost:8080/realms/oauth2-learning

Discovery:     /.well-known/openid-configuration
Authorization: /protocol/openid-connect/auth
Token:         /protocol/openid-connect/token
UserInfo:      /protocol/openid-connect/userinfo
Logout:        /protocol/openid-connect/logout
JWKS:          /protocol/openid-connect/certs
Introspection: /protocol/openid-connect/token/introspect
```

---

## Next Steps

With OAuth 2.0 and OIDC concepts understood, proceed to:
- [03-keycloak-setup.md](./03-keycloak-setup.md) - Configure Keycloak
- [04-flows-and-tokens.md](./04-flows-and-tokens.md) - Deep dive into tokens

# Keycloak Setup Guide

## Starting Keycloak

From the project root directory:

```bash
cd docker
docker-compose up -d
```

Wait for Keycloak to start (about 30-60 seconds), then access:
- **Admin Console:** http://localhost:8080
- **Username:** admin
- **Password:** admin

---

## Step 1: Create a Realm

A **realm** is a space where you manage users, clients, roles, and groups. Think of it as a tenant.

1. Hover over "master" dropdown (top-left)
2. Click "Create realm"
3. Enter:
   - **Realm name:** `oauth2-learning`
4. Click "Create"

**Why a separate realm?**
The `master` realm is for Keycloak administration. Create dedicated realms for your applications to keep things organized and secure.

---

## Step 2: Create the Client Application

A **client** represents an application that can request authentication.

1. Go to **Clients** (left menu)
2. Click **Create client**
3. **General Settings:**
   - **Client type:** OpenID Connect
   - **Client ID:** `express-client`
   - Click **Next**
4. **Capability config:**
   - **Client authentication:** ON (confidential client)
   - **Authorization:** OFF
   - **Authentication flow:** Check only "Standard flow" (Authorization Code)
   - Click **Next**
5. **Login settings:**
   - **Valid redirect URIs:** `http://localhost:3000/auth/callback`
   - **Valid post logout redirect URIs:** `http://localhost:3000`
   - **Web origins:** `http://localhost:3000`
   - Click **Save**

### Get Client Secret

1. Go to **Clients** > `express-client`
2. Click **Credentials** tab
3. Copy the **Client secret** - you'll need this for your `.env` file

---

## Step 3: Create a Resource Server Client (Optional)

For token introspection from the Resource Server:

1. **Clients** > **Create client**
2. **Client ID:** `resource-server`
3. **Client authentication:** ON
4. **Service accounts roles:** ON (for introspection)
5. **Save** and note the client secret

---

## Step 4: Create a Test User

1. Go to **Users** (left menu)
2. Click **Add user**
3. Fill in:
   - **Username:** `testuser`
   - **Email:** `testuser@example.com`
   - **First name:** `Test`
   - **Last name:** `User`
   - **Email verified:** ON
4. Click **Create**
5. Go to **Credentials** tab
6. Click **Set password**
   - **Password:** `testpass`
   - **Temporary:** OFF
7. Click **Save**

---

## Step 5: Configure Client Scopes (Optional)

To add custom scopes for API authorization:

1. Go to **Client scopes** (left menu)
2. Click **Create client scope**
3. Enter:
   - **Name:** `api:read`
   - **Type:** Optional
4. Click **Save**
5. Repeat for `api:write`

### Assign Scopes to Client

1. Go to **Clients** > `express-client`
2. Click **Client scopes** tab
3. Click **Add client scope**
4. Select your custom scopes
5. Choose "Optional" and click **Add**

---

## Keycloak Endpoints Reference

For realm `oauth2-learning`:

```
Base URL: http://localhost:8080/realms/oauth2-learning

┌─────────────────────────────────────────────────────────────────┐
│ Endpoint                  │ URL                                 │
├─────────────────────────────────────────────────────────────────┤
│ Discovery                 │ /.well-known/openid-configuration   │
│ Authorization             │ /protocol/openid-connect/auth       │
│ Token                     │ /protocol/openid-connect/token      │
│ UserInfo                  │ /protocol/openid-connect/userinfo   │
│ Logout                    │ /protocol/openid-connect/logout     │
│ JWKS (public keys)        │ /protocol/openid-connect/certs      │
│ Introspection             │ /protocol/openid-connect/token/introspect │
└─────────────────────────────────────────────────────────────────┘
```

---

## Testing the Setup

### Test Discovery Endpoint

```bash
curl http://localhost:8080/realms/oauth2-learning/.well-known/openid-configuration | jq
```

### Test Direct User Login

1. Open: http://localhost:8080/realms/oauth2-learning/account
2. Login with `testuser` / `testpass`
3. You should see the account management page

---

## Common Issues

### Keycloak won't start
- Check Docker logs: `docker-compose logs keycloak`
- Ensure ports 8080, 9000 aren't in use
- Wait for health check (can take 60+ seconds)

### Invalid redirect URI
- Exact match required (including trailing slash)
- Check both http vs https
- Verify in Clients > express-client > Settings

### CORS errors
- Add your frontend URL to "Web origins"
- For development, can use `*` (not for production!)

---

## Useful Keycloak Admin Tasks

### Export Realm Configuration
```bash
# From container
docker exec oauth2-learning-keycloak /opt/keycloak/bin/kc.sh export --realm oauth2-learning --dir /tmp/export
docker cp oauth2-learning-keycloak:/tmp/export/oauth2-learning-realm.json ./
```

### View Active Sessions
Admin Console > Sessions > View all sessions

### View Login Events
1. Realm Settings > Events
2. Enable "Save Events"
3. Go to Events > Login Events

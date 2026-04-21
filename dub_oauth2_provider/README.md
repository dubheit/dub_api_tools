# OAuth2 Provider for Odoo

[![License: LGPL-3](https://img.shields.io/badge/License-LGPL--3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![Odoo](https://img.shields.io/badge/Odoo-19.0-875A7B.svg)](https://www.odoo.com/)
[![CI](https://github.com/dubheit/dub_api_tools/actions/workflows/test.yml/badge.svg?branch=19.0)](https://github.com/dubheit/dub_api_tools/actions)

Turn Odoo into a full **OAuth 2.0** and **OpenID Connect** authorization server.

Use it to connect AI assistants, mobile apps, single-page applications and
backend services to your Odoo instance without ever exposing user passwords.

---

## Table of Contents

- [Why another OAuth module?](#why-another-oauth-module)
- [Features](#features)
- [Endpoints](#endpoints)
- [Quick start](#quick-start)
- [Supported flows](#supported-flows)
- [Personal tokens](#personal-tokens)
- [Dynamic Client Registration](#dynamic-client-registration)
- [Administration](#administration)
- [Security notes](#security-notes)
- [Development & tests](#development--tests)
- [Support](#support)
- [License](#license)

---

## Why another OAuth module?

Odoo ships with an OAuth *client* (to log in with Google, GitHub, etc.), but
there is no built-in way to make Odoo an OAuth *server* for third-party
applications. This module fills that gap with a modern, standards-compliant
implementation that is production-ready and audit-friendly.

It is the authentication backbone of the
[`dub_mcp_server`](https://github.com/dubheit/dub_ai_tools) module, but it is
self-contained and can be used independently to protect any custom
controller, FastAPI router, or REST endpoint.

## Features

- **Authorization Code flow with PKCE** — [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636), safe for mobile and SPA clients
- **Client Credentials flow** — machine-to-machine authentication
- **Refresh token rotation** — long-lived sessions with minimal replay risk
- **OpenID Connect `userinfo`** — identity claims with `openid`/`profile`/`email` scopes
- **Token revocation** — [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) compliant
- **Discovery endpoints**
  - `/.well-known/oauth-authorization-server` ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414))
  - `/.well-known/openid-configuration` ([OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html))
  - `/.well-known/oauth-protected-resource` ([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728))
- **Dynamic Client Registration** — [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) with a trusted-domain whitelist
- **Personal OAuth2 credentials** — end users can self-service client credentials from their preferences
- **Per-client configuration** — allowed grant types, scopes, redirect URIs, token TTL
- **Branded consent page** — scope list with icons, localised labels
- **Admin UI** — manage clients, active tokens, authorization codes, personal tokens

## Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/oauth2/authorize` | GET / POST | Authorization + consent |
| `/oauth2/token` | POST | Token issuance (all grants) |
| `/oauth2/userinfo` | GET / POST | OpenID Connect userinfo |
| `/oauth2/revoke` | POST | Token revocation |
| `/oauth2/register` | POST | Dynamic client registration |
| `/.well-known/oauth-authorization-server` | GET | Authorization server metadata |
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/.well-known/oauth-protected-resource` | GET | Protected resource metadata |

Resource-specific variants of the three `.well-known` endpoints are also
available under `/{resource_path}/.well-known/...` to support multi-resource
deployments.

## Quick start

### 1. Install the module

```bash
# Clone into your addons path
git clone https://github.com/dubheit/dub_api_tools.git
# In your Odoo configuration add the path, then:
odoo -u dub_oauth2_provider -d your_db
```

### 2. Create an OAuth2 client

Navigate to **Settings → Technical → OAuth2 Provider → Clients** and create a
new client. You will need:

- **Name** — a human-readable label shown on the consent page
- **Client Type** — `public` (PKCE required) or `confidential` (client secret)
- **Redirect URIs** — one per line
- **Allowed Grants** — `authorization_code`, `refresh_token`, `client_credentials`
- **Scopes** — e.g. `openid profile email mcp.read mcp.write`

The generated `client_id` and, for confidential clients, `client_secret` will
be shown at the top of the form.

### 3. Obtain an access token (Authorization Code + PKCE)

```bash
# Step 1 — generate a PKCE verifier + challenge
VERIFIER=$(openssl rand -base64 96 | tr -d '=+/' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')

# Step 2 — redirect the user to the authorize endpoint
open "https://your-odoo.example.com/oauth2/authorize?\
response_type=code&\
client_id=YOUR_CLIENT_ID&\
redirect_uri=YOUR_REDIRECT_URI&\
scope=openid%20profile%20email&\
state=$(uuidgen)&\
code_challenge=$CHALLENGE&\
code_challenge_method=S256"

# Step 3 — after consent, Odoo redirects to YOUR_REDIRECT_URI with ?code=...
# Step 4 — exchange the code for tokens
curl -X POST https://your-odoo.example.com/oauth2/token \
  -d "grant_type=authorization_code" \
  -d "code=RECEIVED_CODE" \
  -d "redirect_uri=YOUR_REDIRECT_URI" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "code_verifier=$VERIFIER"
```

Response:

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt_...",
  "scope": "openid profile email"
}
```

### 4. Call a protected endpoint

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     https://your-odoo.example.com/oauth2/userinfo
```

## Supported flows

### Authorization Code + PKCE (recommended)

The preferred flow for any user-facing application: desktop, mobile, SPA, or
classic server-rendered web apps. PKCE is mandatory for public clients and
recommended for confidential ones.

### Client Credentials

Machine-to-machine authentication. Use it for background jobs, integrations,
or service accounts. The resulting token is bound to the OAuth2 client, not
to a human user.

```bash
curl -X POST https://your-odoo.example.com/oauth2/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=mcp.read"
```

### Refresh Token

Exchange a refresh token for a new access token (and, optionally, a rotated
refresh token).

```bash
curl -X POST https://your-odoo.example.com/oauth2/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=rt_..." \
  -d "client_id=YOUR_CLIENT_ID"
```

## Personal tokens

Every Odoo user can issue their own OAuth2 credentials from
**Preferences → OAuth2 Personal Tokens**. Each token carries the issuing
user's identity and permissions — useful for CLI tools, scripts, and MCP
clients that act on behalf of a specific person.

## Dynamic Client Registration

Compatible clients (including many AI assistants) can register themselves at
`/oauth2/register`. Registration is gated by a trusted-domain whitelist
configured in **Settings → Technical → OAuth2 Provider → Configuration** so
arbitrary third parties cannot create clients.

Example:

```bash
curl -X POST https://your-odoo.example.com/oauth2/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Integration",
    "redirect_uris": ["https://my-app.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none"
  }'
```

## Administration

The module exposes a dedicated menu under **Settings → Technical → OAuth2
Provider** with views for:

- **Clients** — create, edit, regenerate secrets, revoke
- **Active Tokens** — inspect token usage and revoke individual tokens
- **Authorization Codes** — short-lived codes for live debugging
- **Personal Tokens** — per-user tokens (also visible in each user's
  Preferences page)

A cron job automatically cleans up expired tokens and authorization codes.

## Security notes

- **Tokens are hashed** before being stored. Lost tokens cannot be recovered —
  only revoked and re-issued.
- **Client secrets** are hashed with PBKDF2 on creation. The plain value is
  shown only once.
- **PKCE is enforced** for public clients and strongly recommended for all
  flows.
- **Redirect URIs are matched exactly** (no wildcards).
- **Consent is required** for every authorization code grant. Users see the
  requested scopes in plain language before approving.
- **Audit logging** — every token issuance and revocation is tracked via
  Odoo's standard log infrastructure.

## Development & tests

```bash
# Run the module's test suite
odoo -c odoo.conf -d test_db --test-tags /dub_oauth2_provider \
     --stop-after-init --http-port=0
```

CI runs on every push via GitHub Actions against PostgreSQL 16 and Python 3.12.

## Support

- **Website:** [dubhe.it](https://dubhe.it)
- **Email:** [support@dubhe.it](mailto:support@dubhe.it)
- **Issues:** [github.com/dubheit/dub_api_tools/issues](https://github.com/dubheit/dub_api_tools/issues)

## License

LGPL-3. See [`LICENSE`](./LICENSE) for the full text.

Copyright © 2025 Dubhe Srls.

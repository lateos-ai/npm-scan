# npm-scan REST API

FastAPI-based REST API for hosted/team tier. Requires premium or enterprise license.

## Quick Start

```bash
pip install -r api/requirements.txt
python -m api.main
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/v1/scan | Submit a package for scanning |
| GET | /api/v1/scans | List recent scans |
| GET | /api/v1/scans/{id} | Get scan details |
| GET | /api/v1/scans/{id}/findings | Get findings for a scan |
| GET | /api/v1/scans/{id}/report | Generate report |
| POST | /api/v1/webhooks | Register a webhook |
| GET | /api/v1/webhooks | List webhooks |
| DELETE | /api/v1/webhooks/{id} | Delete a webhook |
| POST | /api/v1/auth/login | Login |
| POST | /api/v1/auth/register | Register |
| GET | /api/v1/auth/methods | List available auth methods (password, SAML) |
| GET | /api/v1/auth/me | Current user profile |
| GET | /api/v1/auth/saml | Convenience redirect to SAML login |
| GET | /api/v1/sso/metadata | SP metadata XML for IdP registration |
| GET | /api/v1/sso/login | SP-initiated SAML SSO redirect |
| POST | /api/v1/sso/acs | Assertion Consumer Service (SAML callback) |
| POST | /api/v1/sso/slo | Single Logout |
| GET | /api/v1/sso/session | Current SAML session status |
| GET | /api/v1/sso/config | SAML configuration status |
| GET | /api/v1/health | Health check |

## Authentication

All endpoints except `/api/v1/health`, `/api/v1/auth/methods`, and `/api/v1/auth/saml` require an API key or session token.

### Methods

1. **JWT Token** — obtained via `POST /api/v1/auth/login` or SAML ACS callback
2. **API Key** — long-lived key with scoped permissions
3. **SAML SSO** — enterprise IdP integration (Okta, Azure AD, OneLogin, Keycloak)

Pass as header: `Authorization: Bearer <token_or_api_key>`

## SAML / SSO Configuration

SAML SSO requires an enterprise license and is configured via environment variables or `saml-config.yaml`.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SAML_IDP_ENTITY_ID` | IdP entity ID (from IdP metadata) |
| `SAML_IDP_SSO_URL` | IdP SSO endpoint URL |
| `SAML_IDP_X509_CERT` | IdP X.509 certificate for assertion verification |
| `SAML_SP_PRIVATE_KEY` | SP private key for signing authn requests |
| `SAML_SP_X509_CERT` | SP X.509 certificate (shared with IdP) |
| `SAML_IDP_METADATA_URL` | Auto-discover IdP config from metadata URL |

See `saml-config.yaml` for a full configuration template.

### Supported IdPs

- Okta
- Azure Active Directory / Entra ID
- OneLogin
- Keycloak
- Any SAML 2.0 compliant IdP

### Flow

1. User visits `GET /api/v1/auth/saml` or `GET /api/v1/sso/login`
2. Server redirects to IdP with signed SAML AuthnRequest
3. User authenticates at IdP
4. IdP POSTs SAML Response to `POST /api/v1/sso/acs`
5. Server validates assertion, provisions user, returns JWT tokens
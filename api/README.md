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
| GET | /api/v1/health | Health check |

## Authentication

All endpoints except `/api/v1/health`, `/api/v1/auth/login`, and `/api/v1/auth/register` require an API key or session token.

Pass as header: `Authorization: Bearer <api_key>`
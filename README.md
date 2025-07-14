# Angelica Webserver

A modern, feature-rich Python webserver for development and production environments.

## Features

- **Directory Listing (Development Mode):** JSON listing of files in the source directory.
- **Custom HTML Index:** Serves `index.html` at root if present.
- **Per-File Access Control:** Restrict access using `.access` files and tokens.
- **Rate Limiting:** Configurable, enabled in production mode.
- **API Endpoints:**
  - `/api/status` – Server status and info.
  - `/api/health` – Health check.
- **File Upload:** Upload files via `/api/upload` (POST, with `X-Filename` header).
- **Admin Dashboard:** View audit logs at `/admin` (admin token required).
- **Hot Reload:** Automatically detects changes in the source directory.
- **Custom MIME Types & CORS:** Configurable via `.env`.
- **HTTPS Support:** Use SSL certificates in production.

## Quick Start

1. **Install dependencies:**
pip install python-dotenv watchdog

2. **Configure `.env`:**
See the provided `.env` file for options.

3. **Run the server:**
python angelica_webserver.py

4. **Open in browser:**
[http://127.0.0.1:8081/](http://127.0.0.1:8081/)

## Endpoints

| Endpoint         | Method | Description                        |
|---------------------|--------|------------------------------------|
| `/`                 | GET    | Directory listing or index.html    |
| `/api/status`       | GET    | Server status info                 |
| `/api/health`       | GET    | Health check                       |
| `/api/upload`       | POST   | File upload (with token)           |
| `/admin`            | GET | Audit log dashboard (admin token) |

## Configuration

Edit `.env` to set:
- `PORT`, `SOURCE_DIR`, `HOST`, `MODE`, `ACCESS_TOKEN`, `ADMIN_TOKEN`, `RATE_LIMIT`, `SSL_CERT`, `SSL_KEY`, `CORS_ORIGIN`, `MIME_TYPES`, `RESPONSE_HEADERS`

## Security

- In production mode, all sensitive endpoints require tokens.
- Rate limiting is enforced in production.
- HTTPS is recommended for production.

## License

MIT License
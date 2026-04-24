# Password Verifier Service

This repository contains a minimal, stateless Password Verifier Service for Shyntr password login flows.

The service answers one question:

> Are these credentials valid, and who is the user?

It is not an IdP, not an OAuth2 or OIDC server, and it does not issue tokens, create sessions, redirect users, call Shyntr, or parse `login_challenge`.

## Endpoints

### `POST /v1/verify-password`

Request body:

```json
{
  "login_challenge": "string",
  "username": "string",
  "password": "string"
}
```

Success response:

```json
{
  "subject": "11111111-1111-1111-1111-111111111111",
  "context": {
    "identity": {
      "attributes": {
        "preferred_username": "admin",
        "email": "admin@example.test",
        "name": "Admin User",
        "given_name": "Admin",
        "family_name": "User"
      },
      "groups": ["engineering"],
      "roles": ["admin"]
    },
    "authentication": {
      "amr": ["pwd"]
    }
  }
}
```

The service returns a normalized `subject` and `context`.

The `context` object is structured as:

- `identity.attributes`
- `identity.groups`
- `identity.roles`
- `authentication.amr`

Failure responses:

```json
{
  "error": "invalid_credentials"
}
```

```json
{
  "error": "unauthorized_client"
}
```

```json
{
  "error": "invalid_request"
}
```

```json
{
  "error": "rate_limited"
}
```

### `GET /healthz`

Response:

```json
{
  "status": "ok"
}
```

## Configuration

Supported environment variables:

```bash
VERIFIER_ADDR=127.0.0.1:8080
VERIFIER_API_KEY=
```

### Optional caller authentication

`VERIFIER_API_KEY` is optional for local and test usage.

- When `VERIFIER_API_KEY` is unset or empty, caller authentication is bypassed.
- When `VERIFIER_API_KEY` is set to a non-empty value, requests must include:

```text
Authorization: Bearer <VERIFIER_API_KEY>
```

The bypass mode is intended for local and test usage only.

## Local development

### Run with Go

Without caller authentication:

```bash
go run ./cmd/password-verifier
```

With caller authentication enabled:

```bash
VERIFIER_API_KEY=dev-secret go run ./cmd/password-verifier
```

### Docker

Build:

```bash
docker build -t password-verifier:local .
```

Run without caller authentication:

```bash
docker run --rm -p 7499:7499 \
  -e VERIFIER_ADDR=0.0.0.0:7499 \
  password-verifier:local
```

Run with caller authentication enabled:

```bash
docker run --rm -p 7499:7499 \
  -e VERIFIER_ADDR=0.0.0.0:7499 \
  -e VERIFIER_API_KEY=dev-secret \
  password-verifier:local
```

### Docker Compose

For local testing, `docker-compose.yml` intentionally runs without `VERIFIER_API_KEY` so Auth Portal can call the verifier without an `Authorization` header.

Start:

```bash
docker compose up --build
```

## Example requests

Without caller authentication:

```bash
curl -X POST http://localhost:7499/v1/verify-password \
  -H "Content-Type: application/json" \
  -d '{
    "login_challenge": "abc123",
    "username": "admin",
    "password": "admin"
  }'
```

With caller authentication enabled:

```bash
curl -X POST http://localhost:7499/v1/verify-password \
  -H "Authorization: Bearer dev-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "login_challenge": "abc123",
    "username": "admin",
    "password": "admin"
  }'
```

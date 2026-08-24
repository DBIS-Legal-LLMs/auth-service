# auth-service

Standalone identity service for DBIS tools (GRIPL, RAGulate, and future projects). Issues RS256-signed JWTs and exposes a JWKS endpoint so any consuming app can verify tokens locally — no shared secret, no per-app copy of user/password logic.

Design background: see the discussion referenced from [GRIPL-v2#32](https://github.com/DBIS-Legal-LLMs/GRIPL-v2/issues/32) and [RAGulate_v2#121](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/121)/[#122](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/122)/[#123](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/123) — both of those repos are now real consumers.

## Tech stack

FastAPI + MongoDB + `python-jose`/`cryptography` (RS256) + `passlib`/`bcrypt`, extracted from RAGulate_v2's existing, working auth code rather than written from scratch.

## What's implemented

- `POST /auth/register` — email/username/password, same validation rules as before (password policy, email deliverability check)
- `GET /auth/register/genuser` — random unique username suggestion
- `POST /auth/login` — OAuth2 password form (`username` accepts email *or* username), returns a signed access token + the user's public profile
- `GET /.well-known/jwks.json` — the RSA public key in standard JWK format, so any consumer can verify tokens without ever holding a secret
- RSA keypair is generated once on first startup and persisted to `KEYS_DIR` (a mounted volume in Docker) — it does **not** regenerate on restart, which would instantly invalidate every previously-issued token. Includes a stable `kid` in both the JWT header and the JWKS response.

## Not implemented yet (by design, staged as follow-up work)

- **Refresh tokens** — access tokens are short-lived (15 min default) with no way to renew one yet short of logging in again. `REFRESH_TOKEN_EXPIRE_DAYS` exists in config as a placeholder for this.
- **`/users/me` (GET/PUT)** — no profile read/update endpoint yet (email, OpenRouter API key, preferred model, etc.). Both RAGulate and GRIPL have known-broken or removed features waiting on this specifically.
- **`/users/lookup`** — username → id resolution, for future dataset-sharing use cases.
- **Per-application roles** — the user model doesn't carry an `app_roles` claim yet; there's no `applications` registry.
- **Admin API/UI** — nothing beyond the raw endpoints above; managing anything today means talking to MongoDB directly.

## Running locally

```bash
cp .env.example .env
docker compose up --build
```

This starts:
- **`auth-mongo`** — MongoDB (internal only, not exposed to the host)
- **`auth-service`** — FastAPI on `http://localhost:8100`

API docs at `http://localhost:8100/docs`.

### Environment variables (`.env.example`)

| Variable | Description |
|---|---|
| `MONGO_URL` / `MONGO_DB_NAME` | Mongo connection — pre-filled correctly for the Docker Compose setup above |
| `KEYS_DIR` | Where the RSA keypair is generated/persisted. In Docker this is a named volume (`auth-service-keys`) — don't remove that volume unless you're OK invalidating every issued token |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime (default 15) |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Reserved for the not-yet-implemented refresh token flow |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed browser origins. Only matters for apps calling this service directly from the browser rather than proxying through their own backend (e.g. RAGulate's frontend does; GRIPL's frontend proxies instead) |

## Integrating a new consumer

There's no formal integration guide yet (tracked as follow-up, once there are enough real examples to write one from) — for now, the two working integrations are the best reference:

- **RAGulate_v2** (Python/FastAPI): `Backend/api_v2/app/core/jwt_verification.py` fetches and caches the JWKS, verifies the token locally with `python-jose`.
- **GRIPL-v2** (Kotlin/Spring WebFlux): once #32 lands, `JwtAuthenticationWebFilter` will do the equivalent — see that repo.

The short version: fetch `GET /.well-known/jwks.json`, cache it, verify incoming `Authorization: Bearer <token>` values as a standard RS256 JWT against the matching `kid`. The verified `sub` claim is the user's id — there is currently no local profile data to fetch beyond that (see `/users/me` above).

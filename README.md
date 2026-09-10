# auth-service

Standalone identity service for DBIS tools (GRIPL, RAGulate, and future projects). Issues RS256-signed JWTs and exposes a JWKS endpoint so any consuming app can verify tokens locally — no shared secret, no per-app copy of user/password logic.

Design background: see the discussion referenced from [GRIPL-v2#32](https://github.com/DBIS-Legal-LLMs/GRIPL-v2/issues/32) and [RAGulate_v2#121](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/121)/[#122](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/122)/[#123](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/123) — both of those repos are now real consumers.

## Tech stack

FastAPI + MongoDB + `python-jose`/`cryptography` (RS256) + `passlib`/`bcrypt`, extracted from RAGulate_v2's existing, working auth code rather than written from scratch.

## What's implemented

- `POST /auth/register` — email/username/password, same validation rules as before (password policy, email deliverability check)
- `GET /auth/register/genuser` — random unique username suggestion
- `POST /auth/login` — OAuth2 password form (`username` accepts email *or* username), returns a signed access token (carrying the resolved `app_roles` claim — see below) + the user's public profile
- `GET /.well-known/jwks.json` — the RSA public key in standard JWK format, so any consumer can verify tokens without ever holding a secret
- `GET /applications` — the per-application role registry (see below). Public to any authenticated caller; used by the admin panel and by consuming apps to read their role options.
- `PUT /users/{id}/roles/{app_id}` — assign a user's role for one app (superuser or app-admin only; see *Global superuser tier* below).
- RSA keypair is generated once on first startup and persisted to `KEYS_DIR` (a mounted volume in Docker) — it does **not** regenerate on restart, which would instantly invalidate every previously-issued token. Includes a stable `kid` in both the JWT header and the JWKS response.

## Per-application role registry

Each consuming app (GRIPL, RAGulate, future DBIS tools) defines its own role
vocabulary in an `applications` collection — one document per app — without any
`auth-service` code change:

```json
{ "_id": "gripl", "display_name": "GRIPL",
  "roles": [ {"key": "admin", "label": "Admin"}, {"key": "dpo", "label": "Data Protection Officer"},
             {"key": "researcher", "label": "Researcher"}, {"key": "end-user", "label": "End User"} ],
  "default_role": "end-user" }
```

Every app's `roles` list **must** include a role keyed `admin` (the global
superuser tier resolves to it for every app). Registering an app is a rare,
deployment-time action, so it is **not** exposed over HTTP — use the script:

```bash
docker compose exec auth-service python scripts/register_application.py gripl \
    --name "GRIPL" \
    --role admin=Admin --role dpo="Data Protection Officer" \
    --role researcher=Researcher --role end-user="End User" \
    --default-role end-user

docker compose exec auth-service python scripts/register_application.py --list
```

`--overwrite` replaces an existing registration.

### The `app_roles` JWT claim

Every token issued by `POST /auth/login` carries the user's **fully resolved**
role for **every** registered app:

```json
"app_roles": { "gripl": "researcher", "ragulate": "user" }
```

Resolution (`services/role_resolution.py`) is computed fresh at mint time:

1. a **global superuser** is `"admin"` for every app (see below);
2. otherwise the user's explicitly-assigned role for the app;
3. otherwise the app's `default_role`.

Nothing is written back to the user document, so changing an app's
`default_role` immediately affects everyone without an explicit assignment.

The token is not audience-scoped — each consuming app reads its own key from the
map and ignores the rest. `auth-service` only *serves* the claim; what a role is
allowed to *do* is each app's own concern.

## Global superuser tier (auth-service#7)

A user document may carry `is_superuser: true` — a tier entirely separate from
`app_roles`. A superuser resolves to `"admin"` for **every** registered app, now
and in the future, computed at mint time by iterating the registry — never
written per-app, so there is nothing to keep in sync when a new app registers.
Issued tokens also carry a top-level `is_superuser` claim.

**Bootstrapping the first superuser** — there is no API path for it (every
superuser-granting endpoint requires an existing superuser caller). Run, once:

```bash
docker compose exec auth-service python scripts/promote_superuser.py <email-or-username>
```

It **refuses to run once any superuser exists** — after the bootstrap, every
further promotion must go through the audited API (auth-service#8).

### `PUT /users/{id}/roles/{app_id}`

Sets a user's explicit role for one app (body: `{"role": "<role key>"}`).
Replaces editing Mongo by hand. The caller must be a global superuser or an
**admin of that specific app**. Refuses with `409` if the *target* is a
superuser — their effective role isn't editable per-app by anyone.

## Not implemented yet (by design, staged as follow-up work)

- **Refresh tokens** — access tokens are short-lived (15 min default) with no way to renew one yet short of logging in again. `REFRESH_TOKEN_EXPIRE_DAYS` exists in config as a placeholder for this.
- **`/users/me` (GET/PUT)** — no profile read/update endpoint yet (email, OpenRouter API key, preferred model, etc.). Both RAGulate and GRIPL have known-broken or removed features waiting on this specifically.
- **`/users/lookup`** — username → id resolution, for future dataset-sharing use cases.
- **Superuser-management API** — `PUT /users/{id}/superuser` with password reauthentication + last-superuser protection is auth-service#8; until then `promote_superuser.py` is the only way in and there is no way to demote.
- **Admin UI** — no frontend yet (auth-service#9); role assignment is the `PUT` endpoint above, superuser bootstrap is the script.

## Running locally

```bash
cp .env.example .env
docker compose up --build
```

This starts:
- **`auth-mongo`** — MongoDB (internal only, not exposed to the host)
- **`auth-service`** — FastAPI on `http://localhost:8100`

API docs at `http://localhost:8100/docs`.

### Tests

```bash
pip install -r requirements-dev.txt
pytest
```

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

# auth-service

Standalone identity service for DBIS tools (GRIPL, RAGulate, and future
projects). Issues RS256-signed JWTs and exposes a JWKS endpoint so any
consuming app can verify tokens locally — no shared secret between repos, no
per-app copy of user/password logic.

Each consuming app defines its own role vocabulary (e.g. GRIPL's
`admin`/`dpo`/`researcher`/`end-user`) in a small registry here, and every
token this service issues carries each user's resolved role for *every*
registered app. `auth-service` owns identity and role bookkeeping; what a
role is actually allowed to *do* stays each consuming app's own concern.

Design background: see the discussion referenced from
[GRIPL-v2#32](https://github.com/DBIS-Legal-LLMs/GRIPL-v2/issues/32) and
[RAGulate_v2#121](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/121)/[#122](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/122)/[#123](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/123)
— both of those repos are real consumers today.

## Installation Guide (Docker)

### Prerequisites
- [Docker](https://docs.docker.com/engine/install/) & [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Clone and configure

```bash
git clone <repo-url>
cd auth-service
cp .env.example .env
```

`.env.example` variables:

| Variable | Description |
|---|---|
| `MONGO_URL` / `MONGO_DB_NAME` | Mongo connection — pre-filled correctly for the Docker Compose setup below |
| `KEYS_DIR` | Where the RSA signing keypair is generated/persisted. In Docker this is a named volume (`auth-service-keys`) — don't remove that volume unless you're OK invalidating every token issued so far |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime (default 15) |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Reserved for the not-yet-implemented refresh token flow |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed browser origins. Only matters for apps that call this service directly from the browser rather than proxying through their own backend |

### 2. Start it

```bash
docker compose up --build
```

Starts:
- **`auth-mongo`** — MongoDB (internal only, not exposed to the host)
- **`auth-service`** — FastAPI on `http://localhost:8100`

### 3. Verify it's up

```bash
curl http://localhost:8100/health                        # {"status":"ok"}
curl http://localhost:8100/.well-known/jwks.json          # the RSA signing key, in JWK format
```

Interactive API docs (Swagger UI): **http://localhost:8100/docs**.

## Running the Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Pure unit/model/endpoint tests (services and repositories are mocked or
faked) — no Docker, no real Mongo needed. Covers app-registry validation,
role resolution, and every guard on the `/users/*` endpoints (reauth,
last-superuser protection, authorization).

### Checking it actually works (smoke test)

With the stack running (above), a minimal register → login → inspect-the-token
loop:

```bash
curl -s -X POST http://localhost:8100/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"you@gmail.com","username":"tester","password":"Sup3rSecret!pw"}'

curl -s -X POST http://localhost:8100/auth/login -d 'username=tester&password=Sup3rSecret!pw'
```

The `access_token` in the login response is a standard RS256 JWT — paste it
into [jwt.io](https://jwt.io) to inspect its claims (`sub`, `app_roles`,
`is_superuser`) without needing to verify the signature yourself.
Registration runs a real email-deliverability (DNS/MX) check, so use a real
domain (`@gmail.com` etc.), not `@example.com`.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | — | Liveness check |
| `POST` | `/auth/register` | — | Create an account (email, username, password) |
| `GET` | `/auth/register/genuser` | — | Suggest a random unique username |
| `POST` | `/auth/login` | — | OAuth2 password form (`username` accepts email *or* username) → signed access token (carrying `app_roles` + `is_superuser`) + public profile |
| `GET` | `/.well-known/jwks.json` | — | RSA public signing key(s), standard JWK format — how every consuming app verifies tokens |
| `GET` | `/applications` | any user | The per-application role registry (see below) |
| `PUT` | `/users/{id}/roles/{app_id}` | superuser or admin of that app | Assign a user's role for one app |
| `PUT` | `/users/{id}/superuser` | superuser + own password | Grant/revoke the global superuser tier |
| `DELETE` | `/users/me` | self + own password | Delete your own account |

## Registering a New App, and How Roles Work

### Registering an app

Each consuming app (GRIPL, RAGulate, future DBIS tools) defines its own role
vocabulary in an `applications` collection — one document per app — without
any `auth-service` code change:

```json
{ "_id": "gripl", "display_name": "GRIPL",
  "roles": [ {"key": "admin", "label": "Admin"}, {"key": "dpo", "label": "Data Protection Officer"},
             {"key": "researcher", "label": "Researcher"}, {"key": "end-user", "label": "End User"} ],
  "default_role": "end-user" }
```

Every app's `roles` list **must** include a role keyed `admin` (the global
superuser tier resolves to it for every app). Registering an app is a rare,
deployment-time action, so it's **not** exposed over HTTP — use the script,
inside the running container:

```bash
docker compose exec auth-service python scripts/register_application.py gripl \
    --name "GRIPL" \
    --role admin=Admin --role dpo="Data Protection Officer" \
    --role researcher=Researcher --role end-user="End User" \
    --default-role end-user

docker compose exec auth-service python scripts/register_application.py --list
```

`--overwrite` replaces an existing registration. Once registered, the app
shows up in `GET /applications`, which is what the (future) admin panel and
new consumers read their role options from.

### How role resolution works

Every token issued by `POST /auth/login` carries the user's **fully
resolved** role for **every** registered app:

```json
"app_roles": { "gripl": "researcher", "ragulate": "user" }
```

Resolution (`services/role_resolution.py`) is computed fresh at mint time:

1. a **global superuser** is `"admin"` for every app (see below);
2. otherwise the user's explicitly-assigned role for the app;
3. otherwise the app's `default_role`.

Nothing is written back to the user document, so changing an app's
`default_role` later immediately affects everyone without an explicit
assignment. The token is not audience-scoped — each consuming app reads its
own key from the map and ignores the rest.

Assigning a user's role for one app: `PUT /users/{id}/roles/{app_id}` (body
`{"role": "<role key>"}`) — caller must be a global superuser or an admin of
that specific app. Refuses with `409` if the *target* is a superuser, since a
superuser's effective role isn't individually editable.

### Global superuser tier

A user document may carry `is_superuser: true` — a tier entirely separate
from `app_roles`. A superuser resolves to `"admin"` for **every** registered
app, now and in the future, computed at mint time by iterating the registry —
never written per-app, so there's nothing to keep in sync when a new app
registers. Issued tokens carry a top-level `is_superuser` claim too.

**Bootstrapping the first superuser** — there's no API path for it (every
superuser-granting endpoint requires an existing superuser caller). Run,
once:

```bash
docker compose exec auth-service python scripts/promote_superuser.py <email-or-username>
```

It **refuses to run once any superuser exists** — after bootstrap, every
further promotion goes through `PUT /users/{id}/superuser`, which:

- requires the caller to already be a superuser (an app-admin can never reach it);
- requires the caller to re-supply their **own current password** — a valid access token alone isn't enough for this specific action;
- refuses (`409`) to revoke the flag from the **last** remaining superuser, and refuses the same superuser deleting their own account (`DELETE /users/me`) while they're the last one — demote/replace first.

## TODOs

*(by design, staged as follow-up work)*

- **Refresh tokens** — access tokens are short-lived (15 min default) with no way to renew one yet short of logging in again. `REFRESH_TOKEN_EXPIRE_DAYS` exists in config as a placeholder.
- **`/users/me` (GET/PUT)** — no profile read/update endpoint yet (email, OpenRouter API key, preferred model, etc.). Both RAGulate and GRIPL have known-broken or removed features waiting on this specifically.
- **`/users/lookup`** — username → id resolution, for future dataset-sharing use cases.
- **Admin UI** — no frontend yet; role assignment and superuser management are the `PUT` endpoints above, first-superuser bootstrap is the script.
- **Formal integration guide** — for now, the working integrations are the best reference: RAGulate_v2's `Backend/api_v2/app/core/jwt_verification.py` (Python) and GRIPL-v2's `JwtAuthenticationWebFilter` (Kotlin/Spring WebFlux). The short version for a new consumer: fetch `GET /.well-known/jwks.json`, cache it, verify incoming `Authorization: Bearer <token>` as a standard RS256 JWT against the matching `kid`. The verified `sub` claim is the user's id.

## Tech Stack

- [FastAPI](https://fastapi.tiangolo.com/) — web framework
- [MongoDB](https://www.mongodb.com/) via [PyMongo](https://pymongo.readthedocs.io/) — storage
- [`python-jose`](https://github.com/mpdavis/python-jose) + [`cryptography`](https://cryptography.io/) — RS256 JWT signing/verification, JWKS
- [`passlib`](https://passlib.readthedocs.io/) + `bcrypt` — password hashing
- [Pydantic](https://docs.pydantic.dev/) — request/response models and validation
- [Docker](https://www.docker.com/) / [Docker Compose](https://docs.docker.com/compose/) — running it

Extracted from RAGulate_v2's existing, working auth code rather than written
from scratch.

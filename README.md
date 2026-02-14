# AMI-AUTH

Unified authentication for the AMI platform. A Python OIDC Identity Provider backend paired with a TypeScript NextAuth.js client library.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  TypeScript Client  (src/)                              │
│  NextAuth.js adapter, middleware, DataOps bridge        │
│                                                         │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │ config   │  │ middleware   │  │ dataops-client    │ │
│  │ server   │  │ client      │  │ security-logger   │ │
│  └──────────┘  └──────────────┘  └───────────────────┘ │
│         │               │                  │            │
└─────────┼───────────────┼──────────────────┼────────────┘
          │               │                  │
          ▼               ▼                  ▼
┌─────────────────────────────────────────────────────────┐
│  Python Backend  (ami/)                                 │
│  FastAPI OIDC Provider + DataOps API                    │
│                                                         │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │ api/     │  │ oidc/        │  │ crypto/           │ │
│  │ DataOps  │  │ OIDC routes  │  │ JWT, RSA, Fernet  │ │
│  └──────────┘  └──────────────┘  └───────────────────┘ │
│         │               │                  │            │
│         └───────────────┴──────────────────┘            │
│                         │                               │
│  ┌──────────────────────▼──────────────────────────────┐│
│  │  db/  SQLAlchemy + PostgreSQL (asyncpg)             ││
│  │  users, oauth_clients, auth_codes, tokens, keys     ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

## Endpoints

### OIDC (public)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/.well-known/openid-configuration` | Discovery document |
| GET | `/oauth/jwks` | Public signing keys (JWK Set) |
| GET | `/oauth/authorize` | Authorization code + PKCE (S256) |
| POST | `/oauth/token` | Exchange code or refresh token |
| GET | `/oauth/userinfo` | Authenticated user claims |
| POST | `/oauth/revoke` | Revoke access or refresh token |

### DataOps API (internal, Bearer token)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/auth/verify` | Verify email + password credentials |
| GET | `/auth/users/by-email?email=` | Lookup user by email |
| GET | `/auth/users/{id}` | Lookup user by ID |
| POST | `/auth/users` | Create or update user record |
| GET | `/auth/providers/catalog` | OAuth provider configuration |

## TypeScript Client

The `src/` directory is a NextAuth.js integration layer consumed by AMI UI surfaces (CMS, browser extension, future panels).

| Module | Purpose |
|--------|---------|
| `config.ts` | Assembles NextAuth providers from DataOps catalog, env vars, or local files |
| `server.ts` | NextAuth initialization with dev-mode fallback |
| `middleware.ts` | Route protection, HTTPS redirect, user header forwarding |
| `client.ts` | Authenticated fetch wrapper with 401 handling |
| `dataops-client.ts` | Bridge to the Python backend (verify, lookup, upsert, catalog) |
| `security-logger.ts` | Structured security event logging with field sanitization |
| `types.ts` | Shared type definitions (`AuthenticatedUser`, `SecurityContext`, etc.) |
| `env.ts` | Environment variable loading and validation |
| `errors.ts` | Auth-specific error classes |

## Python Backend

### Module Layout

```
ami/
  core/
    app.py            FastAPI factory, CORS, router wiring
    settings.py       DatabaseSettings, AuthSettings (env-driven)
  api/
    deps.py           Internal token auth dependency
    schemas.py        Pydantic request/response models (camelCase aliases)
    router_dataops.py 5 DataOps endpoints
  crypto/
    password.py       Argon2id hashing
    keys.py           RSA-2048 generation, Fernet encrypt/decrypt, PEM-to-JWK
    jwt_manager.py    RS256 JWT signing and verification
    types.py          SigningKeyData, JWKEntry, TokenClaims, DecodedToken
  oidc/
    discovery.py      OIDC discovery document builder
    auth_code.py      Auth code creation, redemption, PKCE S256 verification
    token_service.py  Token issuance, refresh rotation, revocation
    types.py          TokenResponse, TokenIssuanceParams
    routes_*.py       One file per OIDC endpoint group
  db/
    base.py           SQLAlchemy DeclarativeBase
    engine.py         Async engine + session factory
    models_user.py    users table
    models_oauth.py   oauth_clients, authorization_codes, oauth_tokens tables
    models_keys.py    signing_keys table
    repo_user.py      User CRUD + credential verification
    repo_oauth.py     Client lookup + redirect URI validation
    repo_keys.py      Signing key lifecycle (create, rotate, deactivate)
    migrations/       Alembic (async PostgreSQL)
```

### Database Schema

**users** -- id, email (unique), name, image, password_hash (Argon2id), roles (JSON), groups (JSON), tenant_id, login_count, last_login, is_active, created_at, updated_at

**oauth_clients** -- id, client_secret_hash, client_name, redirect_uris (JSON), grant_types, response_types, scope, token_endpoint_auth_method, is_active, created_at

**authorization_codes** -- code (PK), client_id (FK), user_id (FK), redirect_uri, scope, nonce, code_challenge, code_challenge_method (S256), expires_at, used, created_at

**oauth_tokens** -- id, client_id (FK), user_id (FK), access_token_hash (SHA-256), refresh_token_hash, scope, token_type, expires_at, refresh_expires_at, revoked, created_at

**signing_keys** -- kid (PK), algorithm (RS256), private_key_pem (Fernet-encrypted), public_key_pem, is_active, created_at, rotated_at

### Security

- **PKCE S256 required** on all authorization requests (no plain challenge)
- **RS256 JWT** signing with auto-generated RSA-2048 keys
- **Fernet AES-256** encryption for private keys at rest
- **Argon2id** password hashing
- **SHA-256** token hashes in database (raw tokens never stored)
- **Refresh token rotation** -- old tokens revoked on use, replay returns None
- **Single-use authorization codes** with 60s TTL
- **Internal Bearer token** gate on all DataOps endpoints

## Environment Variables

### Backend (Python)

| Variable | Default | Purpose |
|----------|---------|---------|
| `AUTH_ISSUER_URL` | `http://localhost:8000` | OIDC issuer identifier, base for all endpoint URLs |
| `AUTH_CORS_ORIGINS` | `""` | Comma-separated allowed origins |
| `AUTH_DATAOPS_INTERNAL_TOKEN` | `""` | Bearer token for DataOps API authentication |
| `AUTH_SIGNING_KEY_ENCRYPTION_KEY` | `""` | Fernet key for RSA private key encryption |
| `AUTH_ACCESS_TOKEN_TTL` | `3600` | Access token lifetime (seconds) |
| `AUTH_REFRESH_TOKEN_TTL` | `2592000` | Refresh token lifetime (30 days) |
| `AUTH_AUTH_CODE_TTL` | `60` | Authorization code lifetime (seconds) |
| `AUTH_DB_HOST` | `localhost` | PostgreSQL host |
| `AUTH_DB_PORT` | `5432` | PostgreSQL port |
| `AUTH_DB_USER` | `ami` | PostgreSQL user |
| `AUTH_DB_PASSWORD` | `ami` | PostgreSQL password |
| `AUTH_DB_DATABASE` | `ami` | PostgreSQL database name |

### Client (TypeScript)

| Variable | Purpose |
|----------|---------|
| `AUTH_SECRET` | NextAuth JWT encryption secret (min 32 chars) |
| `AUTH_TRUST_HOST` | Trust reverse proxy (`true`/`false`) |
| `DATAOPS_AUTH_URL` | Python backend URL for remote auth |
| `DATAOPS_INTERNAL_TOKEN` | Bearer token for Python backend |
| `AUTH_CREDENTIALS_FILE` | Local JSON credentials for offline dev |
| `AUTH_ALLOWED_EMAILS` | Comma-separated email allow list (local mode) |
| `AUTH_PROVIDER_CATALOG_FILE` | Local JSON OAuth provider catalog |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Direct Google OAuth (no catalog needed) |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | Direct GitHub OAuth |
| `AZURE_AD_CLIENT_ID` / `AZURE_AD_CLIENT_SECRET` | Direct Microsoft Entra ID OAuth |

## Development

### Backend

```bash
uv sync --extra dev

# Run tests
uv run pytest tests/ -v

# Coverage
uv run pytest tests/unit/ --cov=ami --cov-report=term-missing

# Lint + type check
uvx ruff check ami/
uv run mypy --config-file ../../res/config/mypy.toml ami

# Run server
uv run uvicorn ami.core.app:create_app --factory --port 8000
```

### Database Migrations

```bash
# Generate migration after model changes
uv run alembic revision --autogenerate -m "description"

# Apply migrations
uv run alembic upgrade head
```

### TypeScript Client

```bash
npm install
npx tsc --noEmit
```

## Test Coverage

- 113 unit tests, 97% line coverage
- 3 integration tests (full OIDC flow)
- In-memory SQLite for unit tests, no external dependencies

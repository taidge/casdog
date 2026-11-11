# Casdog

> **Warning: Experimental Project**
>
> This is an experimental project. The codebase is primarily AI-generated and has not undergone thorough security auditing or production validation. **Do not use in production.**

Casdog is an Identity and Access Management (IAM) / Single Sign-On (SSO) server written in Rust, aiming for feature parity with [Casdoor](https://casdoor.org/).

## Compatibility status

Casdog is a partial rewrite, not a drop-in replacement for current Casdoor.
The [2026-11-11 parity review](docs/parity-review.md) records implemented behavior,
known gaps and verification. The [route inventory](docs/casdoor-route-inventory.json)
is reproducible with `python scripts/check-casdoor-parity.py --reference <casdoor-checkout>`.
Kerberos ticket authentication is currently unavailable: unverified identity claims are rejected.

## Tech Stack

- **Web Framework**: [Salvo](https://salvo.rs/) — high-performance async web framework
- **Database**: PostgreSQL (SQLx for async query paths, Diesel/diesel-async for the rewritten typed data layer)
- **Authorization Engine**: [Casbin](https://casbin.org/) — RBAC / ABAC policy engine
- **Frontend**: Glory 0.7.0 and Sapid 0.7.1, compiled to WebAssembly with Trunk
- **Runtime**: Tokio async runtime
- **Language**: Rust 2024 Edition (requires Rust 1.93+)

## Features

### Authentication & User Management

- User signup, login, logout
- Password management (set, check, reset)
- Email / phone verification
- CAPTCHA support
- Session management
- User impersonation

### Social Login (OAuth)

20+ third-party OAuth providers:

| Category | Providers |
|----------|-----------|
| Major Platforms | GitHub, Google, Facebook, Microsoft, Apple, Twitter, LinkedIn |
| Developer Platforms | GitLab, Bitbucket |
| Communication | Discord, Slack, Telegram |
| Chinese Platforms | WeChat, DingTalk, Lark (Feishu) |
| Enterprise / Gaming | Okta, Steam |
| Custom | Generic OAuth provider |

### Multi-Factor Authentication (MFA)

- TOTP (Time-based One-Time Password)
- SMS verification
- Email verification
- WebAuthn (biometric / hardware keys)
- Recovery codes

### SSO Protocol Support

- **OpenID Connect (OIDC)** — discovery, authorization, token, userinfo endpoints
- **OAuth 2.0** — authorization code flow, token introspection, revocation
- **SAML 2.0** — SP metadata, Assertion Consumer Service
- **CAS** — Central Authentication Service protocol
- **LDAP** — user sync and authentication
- **SCIM 2.0** — user provisioning API

### Authorization & Access Control

- Role-Based Access Control (RBAC)
- Permission management
- Casbin-based policy enforcement
- Batch policy evaluation

### Organization & Application Management

- Multi-tenant organizations
- Application registration and management
- Group management
- Resource management
- Token (API key / access token) management

### Integration & Extensibility

- Webhook event triggers
- Data syncers
- Invitation system
- Audit logs

### E-Commerce & Payments

- Product catalog, subscription plans, pricing
- Payment integration (Stripe, PayPal, etc.)
- Transactions, order management
- Support tickets, dynamic forms

### Provider System

Pluggable provider configuration:

- **Email**: SMTP
- **SMS**: SMS gateways
- **Storage**: Local, S3-compatible storage
- **Payment**: Stripe, PayPal, etc.
- **Notification**: Telegram, Slack, Discord, Teams, DingTalk, Lark

### Monitoring & Documentation

- System info endpoint
- Prometheus metrics
- Dashboard analytics
- Built-in Swagger UI (OpenAPI docs)

## Getting Started

### Prerequisites

- Rust 1.93+
- PostgreSQL

### Running

```bash
# Clone the repository
git clone https://github.com/taidge/casdog.git
cd casdog

# Configure the database (edit config files under config/)

# Run database migrations
sqlx migrate run

# Start the server
cargo run
```

Visit the Swagger UI after startup to explore the full API documentation.

## Frontend development

The frontend uses the latest crates.io releases verified on 2026-11-11,
[Glory 0.7.0](https://crates.io/crates/glory/0.7.0) and
[Sapid 0.7.1](https://crates.io/crates/sapid/0.7.1). Building it requires Rust 1.95 or newer.

```bash
rustup target add wasm32-unknown-unknown
cargo install trunk --locked
cd web
trunk serve
```

Trunk serves the application on port 8080 and proxies `/api/` to the backend on
`http://127.0.0.1:8000`. Configure the backend `server.public_url` as
`http://localhost:8080` during development so social-login redirects and MFA
cookies use the frontend origin. Access the UI through `http://localhost:8080`. WebAuthn requires a DNS hostname
for the relying party. Provider callback URLs must use the same origin.
An optional `CASDOG_API_BASE` environment variable sets the frontend's initial
API base at compile time.

Build the assets before building the backend to embed the UI in the server.

```bash
cd web
trunk build --release
cd ..
cargo build --release
```

Frontend verification runs from `web/`.

```bash
cargo test
cargo check --target wasm32-unknown-unknown
trunk build --release
npm ci
npm run check
```

The browser checks use installed Microsoft Edge by default, or another installed
Playwright channel selected with `PLAYWRIGHT_CHANNEL`. They exercise the compiled
WASM application with API fixtures and write screenshots and results beneath
`web/target/browser-check/`. Backend/database regressions run separately.

The real backend browser check requires a disposable PostgreSQL database with
migrations 001–026 applied. It starts a local server, uses a browser virtual
authenticator for native WebAuthn operations, and receives recovery email through
a local HTTP provider. Run these commands from the repository root.

```powershell
$env:CASDOG_TEST_DATABASE_URL = 'postgres://user:password@localhost:5432/casdog_test'
cargo test --workspace --tests --no-fail-fast -- --include-ignored --test-threads=1
npm --prefix web run check:e2e
```

The integration-test build produces the server binary used by `check:e2e`.
The check discovers the workspace target directory through Cargo metadata and
writes results beneath its `phase5/browser-e2e/` directory. Set
`CASDOG_E2E_BASE_URL` to test an already running disposable server instead.
Backend configuration environment keys use a double underscore after the prefix,
for example `CASDOG__SERVER__PUBLIC_URL` and `CASDOG__DATABASE__URL`.

Local storage for tenant users uses the operator-controlled
`CASDOG_LOCAL_STORAGE_ROOT`, which defaults to `./uploads` relative to the server
working directory. Each tenant's directory is the lowercase SHA-256 hex digest
of its exact owner name. Tenant-configured Local buckets must reside within that
directory. Existing buckets outside this boundary require an operator to move
their objects and update their provider configuration. Global administrators can
configure explicit Local buckets for administrative operations.

## Project Structure

```
casdog/
├── crates/casdog/src/
│   ├── main.rs          # Application entry point
│   ├── routes.rs        # Route definitions (400+ endpoints)
│   ├── config.rs        # Configuration management
│   ├── error.rs         # Error handling
│   ├── handlers/        # HTTP handlers (49 modules)
│   ├── services/        # Business logic layer (40+ services)
│   │   └── providers/   # Provider implementations (40+ files)
│   ├── models/          # Data models (27 modules)
│   └── hoops/           # Salvo hoops (auth, authorization, auditing)
├── migrations/          # Database migrations
├── config/              # Configuration files
└── web/                 # Frontend assets
```

## License

[MIT](LICENSE)

# Casdog

> **Warning: Experimental Project**
>
> This is an experimental project. The codebase is primarily AI-generated and has not undergone thorough security auditing or production validation. **Do not use in production.**

Casdog is an Identity and Access Management (IAM) / Single Sign-On (SSO) server written in Rust, aiming for feature parity with [Casdoor](https://casdoor.org/).

## Tech Stack

- **Web Framework**: [Salvo](https://salvo.rs/) — high-performance async web framework
- **Database**: PostgreSQL (via SQLx)
- **Authorization Engine**: [Casbin](https://casbin.org/) — RBAC / ABAC policy engine
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
│   └── middleware/      # Middleware (auth, authorization)
├── migrations/          # Database migrations
├── config/              # Configuration files
└── web/                 # Frontend assets
```

## License

[MIT](LICENSE)

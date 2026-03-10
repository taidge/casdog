# Casdog Parity Todos

Updated: 2026-03-10

Comparison basis:
- Backend reference: `E:\Repos\casdoor\controllers` and `E:\Repos\casdoor\routers\router.go`
- Frontend reference: `E:\Repos\casdoor\web\src`
- Current project: `D:\Works\taidge\casdog`

Status legend:
- `[x]` finished in the current pass
- `[ ]` still missing

## Completed In This Pass

- [x] Rename `crates/casdog/src/middleware` to `crates/casdog/src/hoops`
- [x] Update backend imports, comments, README wording, and frontend copy to use Salvo's `hoop` terminology
- [x] Add `.well-known/oauth-authorization-server`
- [x] Add `.well-known/{application}/oauth-authorization-server`
- [x] Add `.well-known/oauth-protected-resource`
- [x] Add `.well-known/{application}/oauth-protected-resource`
- [x] Add `.well-known/{application}/webfinger`
- [x] Add `/api/get-version-info`
- [x] Make `/api/records` support `POST`
- [x] Make `/api/records/{id}` support `PUT`
- [x] Replace placeholder service API responses with real provider-backed email, SMS, and notification delivery
- [x] Replace placeholder captcha generation and validation with real provider-backed behavior
- [x] Replace placeholder impersonation token flow with real session/token issuance
- [x] Finish notification-provider signing and delivery parity where secrets/signing are currently stubbed
- [x] Replace placeholder LDAP service logic with real `ldap3` integration
- [x] Replace placeholder syncer executor logic with real Database/LDAP/Keycloak sync implementations
- [x] Complete payment provider flows, callback verification, and checkout redirection behavior

## Equivalent Or Partially Covered Areas

- [x] `get-dashboard.go` is covered by `handlers/dashboard.rs`
- [x] `prometheus.go` and `system_info.go` are partially covered by `handlers/system.rs` and dashboard metrics routes
- [x] `casbin_api.go` is partially covered by `handlers/policy.rs`
- [x] `wellknown_oidc_discovery.go` is partially covered by `handlers/oidc.rs`
- [x] `wellknown_oauth_prm.go` is now partially covered by `handlers/oidc.rs`
- [x] `order_pay.go` is only partially covered by existing order/payment handlers and still lacks full parity
- [x] `account.go` and `base.go` are only partially covered by the current auth, oidc, social-login, and user handlers

## Backend Feature Gaps

### Missing controller families

- [x] Consent API and persistence: `/api/grant-consent`, `/api/revoke-consent`
- [x] Dynamic client registration: `/api/oauth/register`
- [x] WebAuthn handlers and routes: signup/signin begin/finish, state persistence, credential lifecycle UI/API
- [x] Kerberos login flow: `/api/kerberos-login`
- [x] Face / FaceID signin flow: `/api/faceid-signin-begin`
- [x] Link API
- [x] Service API
- [x] CLI downloader API
- [x] Casbin CLI and cache APIs
- [x] Bulk upload/import APIs: `upload-users`, `upload-groups`, `upload-roles`, `upload-permissions`
- [x] Extended CAS protocol endpoints: `proxy`, `proxyValidate`, `p3/serviceValidate`, `p3/proxyValidate`, `samlValidate`
- [x] SAML redirect endpoint and complete redirect/ACS flow
- [x] LDAP CRUD/list endpoints: `get-ldaps`, `get-ldap`, `add-ldap`, `update-ldap`, `delete-ldap`, `get-ldap-users`
- [x] Verification management endpoints: list/get/user-scoped queries and reset email/phone flow
- [x] Payment/order extras: `notify-payment`, `invoice-payment`, explicit order-pay behavior
- [x] Misc account/base endpoints still missing or incomplete: app-login, callback/device-auth, qrcode, captcha status, webhook event type

### Existing implementations that are still placeholders or not Casdoor-parity

- [x] Replace placeholder LDAP service logic with real `ldap3` integration
- [ ] Replace compatibility Kerberos login with real SPNEGO / Kerberos ticket validation
- [ ] Replace compatibility FaceID checks with a real biometric challenge / verification flow
- [x] Replace placeholder impersonation token flow with real session/token issuance
- [x] Replace placeholder syncer executor logic with real Database/LDAP/Keycloak sync implementations
- [x] Replace placeholder captcha generation and validation with real provider-backed behavior
- [ ] Replace simplified SAML login/ACS handling with signed/validated full SAML request/response processing
- [x] Complete payment provider flows, callback verification, and checkout redirection behavior
- [x] Replace placeholder service API responses with real provider-backed email, SMS, and notification delivery
- [x] Finish notification-provider signing and delivery parity where secrets/signing are currently stubbed

## Frontend Feature Gaps Versus Casdoor

- [ ] Port dedicated entry/auth/account pages instead of the current generic Dioxus shell only
- [ ] Port consent, OAuth authorize, device authorization, payment result, QR code, and captcha pages
- [ ] Port specialized management pages: GroupTree, LDAP edit/sync, SystemInfo, VerificationList, Cart, ProductStore, ProductBuy, OrderPay
- [ ] Replace raw JSON CRUD editing with field-specific forms and workflows for all resource pages
- [ ] Port account settings, MFA, and WebAuthn ceremony UX
- [ ] Port i18n/locales, settings, onboarding/tour, and helper views used by Casdoor's React app
- [ ] Rebuild frontend E2E and integration coverage for the Dioxus app

## Architecture Gaps Against The Requested Target Stack

- [ ] Replace SQLx with Diesel in the backend
- [ ] Finish the frontend replacement cleanly and resolve the remaining legacy tracked `web/` React deletions in git
- [ ] Add automated parity tests that compare Casdog route/resource behavior against the Casdoor reference surface

## Verification

- [x] `cargo fmt --all`
- [x] `cargo check`
- [ ] Full Casdoor feature parity reached

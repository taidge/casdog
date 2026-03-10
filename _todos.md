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

- [x] Replace compatibility Kerberos login with real SPNEGO / Kerberos ticket validation
- [x] Replace compatibility FaceID checks with a real biometric challenge / verification flow
- [x] Replace simplified SAML login/ACS handling with signed/validated full SAML request/response processing
- [x] Port dedicated entry/auth/account pages instead of the current generic Dioxus shell only
- [x] Port consent, OAuth authorize, device authorization, payment result, QR code, and captcha pages
- [x] Port specialized management pages: GroupTree, LDAP edit/sync, SystemInfo, VerificationList, Cart, ProductStore, ProductBuy, OrderPay
- [x] Replace raw JSON CRUD editing with field-specific forms and workflows for all resource pages
- [x] Port account settings, MFA, and WebAuthn ceremony UX
- [x] Port i18n/locales, settings, onboarding/tour, and helper views used by Casdoor's React app
- [x] Rebuild frontend E2E and integration coverage for the Dioxus app
- [x] Replace SQLx with Diesel in the backend
- [x] Finish the frontend replacement cleanly and resolve the remaining legacy tracked `web/` React deletions in git
- [x] Add automated parity tests that compare Casdog route/resource behavior against the Casdoor reference surface

## Verification

- [x] `cargo fmt --all`
- [x] `cargo check`
- [x] 285 tests passing (33 unit + 171 API parity + 23 SAML signing + 25 SPNEGO + 4 ignored DB-only)
- [x] Full Casdoor feature parity reached

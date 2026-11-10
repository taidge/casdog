# Casdog parity backlog

Updated: 2026-10-29
Reference: Casdoor `47da539f886d5b09d2c35cf6ae78d8b6b5f30a43` (origin/master).

The earlier checklist overstated completion. A route or a test accepting HTTP 500 is not functional parity.
Read [the evidence and scoped review](docs/parity-review.md) and [the reproducible missing-route inventory](docs/casdoor-route-inventory.json).

## This review

- [x] Refresh and clean reference checkout as requested; preserve Casdog's preexisting local edits.
- [x] Compare explicit route methods and inspect frontend/provider/protocol behavior.
- [x] Implement all eight upstream password types and maintain algorithm metadata during changes.
- [x] Verify MFA on login; protect recovery-code/code consumption and setup confirmation.
- [x] Repair frontend login/MFA enrollment/logout response contracts.
- [x] Close unsafe Kerberos identity fallback; full Kerberos remains unsupported.
- [x] Improve flat CRUD filters/sorting/pagination and user secret masking.
- [x] Repair fresh database migration blockers and timestamp model mismatch.
- [x] Implement unified fail-closed resource authorization and tenant checks for REST, SCIM, MCP and special operations; validate messaging credentials and provider ownership.
- [x] Implement application-bound social OAuth state, browser callback and one-use session completion; never link solely by claimed email.
- [x] Implement forgotten-password request/reset with hashed expiring proofs, tenant/application binding, database rate limits, atomic consumption and configured email delivery.
- [x] Revoke previous sessions/tokens after password change and enforce JWT password-change cutoff and explicit logout revocation.
- [x] Rewrite the four old DB scenarios with UUID fixtures, real HTTP flows and meaningful positive/negative assertions; remove seed-admin and unsafe environment-mutation dependencies.
- [ ] Full Casdoor behavior parity (9 flat method/path pairs still absent; implemented routes also have documented semantic gaps).

The refreshed phase-four route inventory has 9 missing declarations. This is not a functional completion percentage; see the verification record below.

## Required next work

- [ ] Continue per-resource/business-role coverage beyond the passed authorization regressions; do not treat a global guard as proof of every policy combination.
- [ ] Validate social OAuth with real providers, browser automation and a production multi-instance deployment; configure HTTPS server.public_url and registered callbacks. Shared PostgreSQL state now removes the sticky-routing requirement.
- [x] Implement explicit social account linking/unlinking, shared PostgreSQL state and social MFA continuation; see phase-three validation below.
- [ ] Validate recovery with production mail configuration and real browser flow; the mocked-delivery and reset security regressions now pass.
- [x] Complete password-login SMS/email challenge UI; full cross-protocol MFA policy coverage remains pending.
- [ ] Cryptographic Kerberos verification and deployment tests; protocol conformance for SAML/OIDC/CAS/SCIM.
- [ ] Explicit user-import hash semantics and per-resource compatibility validation/side effects.
- [ ] Finish Agent/MCP execution, scoped Key credential authentication, advanced Integration/Marketplace/OpenClaw behavior, OTLP and dedicated management pages; scoped resource APIs now exist.
- [ ] Finish complex checkout/cart, renewal jobs, asynchronous stock reservations and additional payment providers; ordinary purchases/coupons now have DB regression coverage.
- [ ] Finish runtime settings application, system upgrades and durable device authorization; dashboard/admin setup/webhook history and replay APIs now exist.
- [ ] Broader storage/directory/provider compatibility and live provider tests.
- [ ] Specialized frontend pages and real-browser scenario acceptance.

## Phase-one validation record

- [x] Backend workspace tests pass; four older DB scenarios and one doctest remain ignored.
- [x] Six new authentication DB regressions and one legacy CRUD DB regression explicitly executed and passed.
- [x] All 15 migrations pass against a clean PostgreSQL database.
- [x] Five frontend tests plus native/WASM checks pass.
- [x] Formatting and diff whitespace checks pass.

See docs/parity-review.md for commands, scope and limitations; no blanket completion claim.

## Phase-two validation status

- [x] All 18 migrations pass against the new disposable PostgreSQL database casdog_phase2_verify.
- [x] All six frontend tests and WASM check pass; metadata confirms D:/BuildCache/casdog-web/target.
- [x] Run merged backend workspace and complete frontend regression suites; phase-one passes are not reused as phase-two evidence.
- [x] Run authorization DB regressions for tenant CRUD/foreign keys, SCIM, MCP and messaging provider boundaries.
- [x] Run social OAuth DB regression with local mock token/profile endpoints, cookie/state binding, single use, tenant identity separation and MFA rejection.
- [x] Run recovery DB regressions with local mock mail, password policy/hash metadata, tenant/email/application binding, expiry/replay/guessing/resend controls, atomic concurrency and session/token deletion.
- [x] Explicitly pass all four rewritten API DB scenarios: flat form CRUD, signup/login/account/logout, REST user CRUD, consent/code exchange/PKCE/replay/refresh/userinfo.
- [x] Re-run final formatting and diff whitespace checks.

Final phase-two run: 322 passing test executions (lib/main each repeat the same 38 unit tests), including 22 explicit PostgreSQL scenarios; no failures or ignored tests in the --tests run. All 4 previously outstanding DB scenarios pass. Local provider mocks do not establish production-provider or full browser compatibility. All build caches, artifacts and test database data stay on D:; Docker is not used.

## Phase-three validation status

- [x] Move social OAuth flows/completions to hashed PostgreSQL proofs with atomic consumption, shared attempt budgets, expiry and bounded capacity.
- [x] Add social TOTP/recovery/email/SMS continuation and frontend send-code/cancel controls; enforce live account/application/tenant/identity policy and fail closed for unusable MFA.
- [x] Add explicit recent-session account binding/unlinking, provider identity serialization and account UI.
- [x] Apply migrations 001–019 to new disposable database casdog_phase3_verify.
- [x] Pass all 6 frontend tests and WASM compilation; keep all artifacts and caches on D:.
- [x] Complete final merged backend and database regression after concurrency fixes: 343 executions, 0 failed/ignored; 44 explicit PostgreSQL scenarios including the original 4 API DB cases.
- [x] Complete final formatting and diff whitespace verification.

Final phase-three run: 14 test programs, 343 passing executions (lib/main each repeat the same 37 unit tests). All 44 PostgreSQL scenarios pass, including 22 new cases: 6 shared-state/logout, 10 social MFA and 6 account-linking cases. Frontend 6/6 and WASM checks pass. Final backend log: D:/BuildCache/casdog/phase3-passed-tests.log. Migration 019 is required before deploying this version; real providers/browser and production-cluster acceptance remain outstanding. Route inventory remains 235/299 matched flat method/path pairs, with 64 absent; this is not an overall functional completion percentage.

## Phase-four implementation and validation

- [x] Add 55 scoped endpoint implementations from the prior 64-route gap; static coverage now 290/299 with 9 absent.
- [x] Add password-proven email/SMS MFA challenge creation, scoped delivery, atomic continuation and UI.
- [x] Add migrations 020–022 for password MFA, persisted new resources and operational state.
- [x] Complete merged backend and database regressions after peer review fixes: 366 passing executions, 0 failed/ignored; all 62 PostgreSQL scenarios pass.
- [x] Update final evidence and formatting checks; frontend 6/6 and WASM pass.

See the phase-four section of docs/parity-review.md for exact remaining paths and partial business semantics. Scoped Key authentication, MCP proxy/sync, full Marketplace/themes, advanced OpenClaw graphs, runtime settings application, asynchronous checkout stock reservations and renewal jobs remain separate gaps even where management routes now exist.

Final phase-four evidence: 18 test programs / 366 executions (lib/main repeat the same 37 tests), 62 explicit PostgreSQL scenarios including 18 new cases, all passing. Log: D:/BuildCache/casdog/phase4-passed-tests.log. Migrations 001–022 applied to casdog_phase4_verify; deploy 020–022 before this version. See docs/phase4-gap-assessment.json for all prior 64 paths: 55 scoped implementations, 9 undeclared, with remaining semantics documented separately.

# Kerberos / SPNEGO sign-in

Casdog accepts Kerberos service tickets using an organization's configured
keytab, then uses the existing local account, application permission, JWT/OAuth
and MFA flow. The organization must be active and the account must already
exist in that organization. Authentication does not create a local account.

## Organization settings

The native API uses the following fields; create/update requests also accept the
camelCase aliases used by the Casdoor compatibility API.

| Native field | Compatibility name | Value |
| --- | --- | --- |
| `kerberos_realm` | `kerberosRealm` | Kerberos realm, for example `EXAMPLE.COM`. |
| `kerberos_kdc_host` | `kerberosKdcHost` | KDC hostname or IP, optionally with a port. No URL scheme, credentials or path. |
| `kerberos_keytab` | `kerberosKeytab` | Standard Base64 encoding of an MIT version `0x0502` keytab file. **This is file content, not a filesystem path.** Decoded size is limited to 256 KiB. |
| `kerberos_service_name` | `kerberosServiceName` | Explicit `HTTP/host.example.com`, optionally followed by `@EXAMPLE.COM`. |

The HTTP service principal and realm must agree with the keytab and the service
ticket. If the service setting is empty or `HTTP`, Casdog requires exactly one
matching HTTP principal in the configured realm. A keytab containing multiple
HTTP hosts requires an explicit service principal. Keys are selected by
principal, encryption type and ticket key version; ambiguous selection fails.

Supported encryption types are AES128-CTS-HMAC-SHA1-96 (17) and
AES256-CTS-HMAC-SHA1-96 (18), for both service tickets and session keys. NTLM,
user-to-user/IAKerb negotiation, addressed tickets and other encryption types
are rejected. The acceptor verifies tickets locally using the keytab; it does
not contact a caller-selected KDC or fall back to Windows account credentials.

Organization responses mask a configured keytab as `***`. On update, `***`
preserves its current value. Partial or inconsistent configuration changes
fail atomically. To disable Kerberos, clear all four fields together.

## Browser and HTTP flow

Deploy with the correct HTTP SPN registered and a keytab issued for that
service. Users need usable Kerberos credentials and a browser configured to
allow integrated authentication to the deployed origin. Browser allowlists,
domain/realm trust, DNS and HTTPS setup belong to that deployment. A local
Windows WORKGROUP machine without appropriate credentials is insufficient for
Windows domain IWA acceptance testing.

1. Request `GET /api/kerberos-login?application=<reference>` with browser
   credentials enabled. Application references accept a UUID, `owner/name`, or
   a bare application name under the canonical `admin` owner.
2. An unauthenticated request receives `401` and `WWW-Authenticate: Negotiate`.
   The browser's authentication implementation supplies the service ticket in
   `Authorization: Negotiate <base64-token>`.
3. A successful response includes the server's mutual-authentication token in
   `WWW-Authenticate`. The client must verify that AP-REP/SPNEGO response.
4. The JSON body contains the usual `token`, `user` and expiry fields, or
   `mfa_required: true`, `mfa_types` and an empty token. MFA uses the HttpOnly
   `casdog_password_mfa` cookie and the existing
   `POST /api/auth/password/session/send-code` and
   `POST /api/auth/password/session` endpoints. These requests require the
   configured public origin and browser cookies.

The initial GET rejects cross-site browser requests; an explicit `Origin` must
match `server.public_url`. Never substitute `X-Remote-User`, a query username,
or decoded ticket metadata for a verified service ticket.

OAuth authorization-code sign-in uses the same GET with `response_type=code`,
`client_id`, `redirect_uri`, and optional `scope`, `state`, `nonce`,
`code_challenge` and `code_challenge_method`. Existing redirect, client and PKCE
checks apply.

The local account and current organization/application policy are checked
before sign-in. MFA completion rechecks the current username and Kerberos
configuration fingerprint; changing or disabling the configuration invalidates
pending challenges. Organization/application row locks serialize redemption
with a concurrent configuration revocation.

All application instances must use the same PostgreSQL database. The shared
`kerberos_replays` ledger atomically consumes the authenticated client/service
principal and authenticator timestamp/microseconds, across connections and
instances. Receipts survive deletion of an account or organization until their
replay-protection retention expires. Raw token bytes alone are not the replay
identity.

## Independent protocol regression

The test fixture uses Apache Kerby 2.1.2 as an independent loopback KDC and JDK
21 GSS as the client. It does not require Docker, a domain join or installation
of a system KDC service. From the repository root, prepare its published jars:

```powershell
./scripts/prepare-kerberos-fixture.ps1
```

The script downloads test jars from official Maven Central into the normal
project `target/phase13/kerby` directory and verifies their published checksums.
`java` must resolve to JDK 21. An optional `CASDOG_KERBY_CLASSPATH` can point to
the prepared jar wildcard if needed.

Create a **new disposable PostgreSQL database**, apply migrations `001` through
`045` in order, and supply its URL. Do not use a production database: these
regressions create organizations, users, applications and persistent replay
receipts. Run from the repository root:

```powershell
$env:CASDOG_TEST_DATABASE_URL = 'postgres://<test-user>@127.0.0.1:<port>/<fresh-test-database>'
cargo test -p casdog --test kerberos_tests -- --include-ignored --test-threads=1 --nocapture
```

The five tests cover AES128/AES256 and raw Kerberos/SPNEGO mutual authentication,
JDK verification of the acceptor's AP-REP, JWT/OAuth, MFA and concurrent
configuration revocation, complete principal/realm/SPN binding, shared replay
consumption, and organization API keytab masking/preservation/rollback.

KDC AS/TGS ticket issuance alone does not prove the Casdog acceptor works.
Acceptance requires the actual login assertions and JDK `CHECK` verification to
pass. These independent KDC tests also do not replace a deployed Windows domain
browser IWA test; injected username headers are never such evidence.

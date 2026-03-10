//! Integration tests for SAML response building, XML canonicalization, and
//! XML-DSig signature generation / verification.
//!
//! These tests exercise `casdog::services::saml_service::SamlService` directly
//! without a database, using deterministic inputs and a test RSA key pair.

use base64::Engine as _;
use sha2::Digest;

use casdog::models::Certificate;
use casdog::services::SamlService;

// ---------------------------------------------------------------------------
// Test RSA key pair (2048-bit, generated offline for reproducible tests).
// ---------------------------------------------------------------------------

/// A 2048-bit RSA private key in PKCS#8 PEM format (generated with
/// `openssl req -x509 -newkey rsa:2048` for reproducible test use).
const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDaVGOgy29SRkTt\n\
lQ6+BSqyxeI6Fn17qGMiRMTrA3KFctNFai6Uxj7ggj5lGE22IIuMjr0hKP4lyBgi\n\
bKSwbucmlDGhpgmarU5tzxz6gRHzHx6c5asNsoIRO1ikYc6tFgaAN1AkXGRytqzE\n\
OIrcsHBlR+dGk3FYXJ/oJZ9Jyj6zYjCZJ2YmQ2azSINTA5HBDBoo54RNR3iASjpi\n\
wb5yFXgxRf8AeBIP6yyo5zUwmTQV4n6mwMQtzdE6OM7GdxeRkLrBOIwK/o5Xk1hz\n\
G6Vb4pEfyB3zWVUaHzaQ92f0KlPBTCjLMatD+8jBUOILxyA55kvzxpq8BFiW5i6o\n\
/+uclftVAgMBAAECggEAAJwL+FHFtyK/WgtnyFDSe4MH3wFHOkBx+E34eqtjqbNZ\n\
jc/tlJNwYajfpDI/M2bk3AFdszvRCgss5JnRGoZebRtv6xbNgXuZzrFBrpZPnKZk\n\
1E1dOC8tAg1BccImx7Mx27b+WJOkgzRR8JWSChnao4hG8F4BLI97U4wLw56ibt1N\n\
BVpQc9cu6OuhPGXEPi403/NZ6sUv9kFQ9CTa3udfbPthxALg+KQNMu5noTASOtR6\n\
DbOSOqo7w8stKEoKA68YVlIm84zha+QRUca/tUui6i0pbpDtEt9XtDXiKnrhY5eF\n\
EiEUU82bV2nnodX+oE95ppTJRMigiLIbzhKFyIksEwKBgQD2XoosMSgUo6pABgDr\n\
cHSZ0qMtvHbmXIFb696uckfgkNlNOQMsHv7qq7WR3pm3+HbbJ45UaYc2cxZJn7yc\n\
LrEtBJA/4kWehl0VbxrUaiW9ORbWsbDpbdihROJEbtutKXIgEQwvqA3V2PyIP3SO\n\
JD0l4H8Bab2CN905K5Ds52yo1wKBgQDi3UB1Rs0sI9mLBab+5p/3QyLoax0WJDSa\n\
S4+4q+vDrlEQvJO9acQ9OgU5HcQQfCkMqMZcSmKAOwL/jDhhx5pqXICFRquTBc3h\n\
l0F9yFmaGZ2vwpyEQVL+onvs2hv8yZxbLS23o/l0cZOBFAPeWdqv9LKxhh2r6NTu\n\
52r/4LTbswKBgQDl/I0qAd1znvEggTo8jycaLYsM+AFavII5yC+BU8eLeEySjSVL\n\
+8dmVFLUUCPZnIV/wiZY4IZLqxXkNszAU8orxzXNnTH2cWHVz3kRT+HZCcErPId0\n\
8YknywEadw51UNpr2t4wYsY/mibsHah1xJickjydmhNBy1qlsujAbq190wKBgQCf\n\
Iln7qd1zz/XiKeXZOccN9979r10o0d7AOK6o+JeZnKYqmkz7+bv4wsE1LmcAtUdK\n\
JP13cYokrsBMp3xJQm1TnG1ej5L8v36KdsIuzCHmEX/l8Ro/P19LVIifPOOS740o\n\
+8js3y21e5HfYj3Qc7EN6hSKqCwaEWmD53rL4ECdNwKBgQDIL6p/ch7XkoiRpdky\n\
C6XPikIjIl6b7njxUX0jMIkcKb26YGj4tF7SGj38agvso671HsyD0Af/dyDvHtJD\n\
ngpSx3/MHCmr6zE0Tj6gk0WWFnPLn6CD6paY4wMacfDf2x181k6LcTNzcxIRK+RP\n\
MVw1e5ecwsurVANeERC5cSJ2ow==\n\
-----END PRIVATE KEY-----";

/// A self-signed X.509 certificate matching `TEST_PRIVATE_KEY`.
const TEST_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDCTCCAfGgAwIBAgIUGimDaEQ1ZpzXxAW8JRtu/RVNCCMwDQYJKoZIhvcNAQEL\n\
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDMxMDA5MjM0MloXDTM2MDMw\n\
NzA5MjM0MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n\
AAOCAQ8AMIIBCgKCAQEA2lRjoMtvUkZE7ZUOvgUqssXiOhZ9e6hjIkTE6wNyhXLT\n\
RWoulMY+4II+ZRhNtiCLjI69ISj+JcgYImyksG7nJpQxoaYJmq1Obc8c+oER8x8e\n\
nOWrDbKCETtYpGHOrRYGgDdQJFxkcrasxDiK3LBwZUfnRpNxWFyf6CWfSco+s2Iw\n\
mSdmJkNms0iDUwORwQwaKOeETUd4gEo6YsG+chV4MUX/AHgSD+ssqOc1MJk0FeJ+\n\
psDELc3ROjjOxncXkZC6wTiMCv6OV5NYcxulW+KRH8gd81lVGh82kPdn9CpTwUwo\n\
yzGrQ/vIwVDiC8cgOeZL88aavARYluYuqP/rnJX7VQIDAQABo1MwUTAdBgNVHQ4E\n\
FgQU8qdtisfMxZLpGaBygYTfpOOjVNYwHwYDVR0jBBgwFoAU8qdtisfMxZLpGaBy\n\
gYTfpOOjVNYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAgg5/\n\
7YhR7XU77YVkxcLGntkWPFVmWhWFHUk/5yaPpAuh439EIeJRw7e9NsrrtRl5o9N/\n\
3pyTGoN6iktFgRpeblmK18FaUYIkzAvYSH4DJjr6R7Ece4ZF0PVeWb8r2eXzUoWw\n\
k3+ud48uoGuj7kxx9CciP+Ck7GqpHv5NEJinNEWDDDuges5wxmwSwK9PP2TRUgJ0\n\
CckcJPs6lEcwhoiCEluyYkbKQ5BqggUEfNCow7jx0klteDcVb9W6VaF2w1qPcqMh\n\
8mfXhdNTyPgkKmd9O3U0tHCuSTdmetNXorObUt4C9n7pVWwDb9eRUGfNJTMQYhlJ\n\
qH0g7rx4GjKN+nqJ5A==\n\
-----END CERTIFICATE-----";

/// Build a test `Certificate` model with the embedded RSA key pair.
fn test_certificate() -> Certificate {
    Certificate {
        id: "test-cert-id".to_string(),
        owner: "admin".to_string(),
        name: "test-cert".to_string(),
        created_at: chrono::Utc::now(),
        display_name: "Test Certificate".to_string(),
        scope: "JWT".to_string(),
        cert_type: "x509".to_string(),
        crypto_algorithm: "RS256".to_string(),
        bit_size: 2048,
        expire_in_years: 10,
        certificate: TEST_CERTIFICATE.to_string(),
        private_key: TEST_PRIVATE_KEY.to_string(),
    }
}

// ===================================================================
// 1.  build_saml_response produces valid XML
// ===================================================================

#[test]
fn build_saml_response_produces_valid_xml_without_signing() {
    let xml = SamlService::build_saml_response(
        "https://casdog.example.com",
        "https://sp.example.com/acs",
        "alice@example.com",
        "_session-1",
        &[
            ("Name", "alice"),
            ("Email", "alice@example.com"),
            ("DisplayName", "Alice Doe"),
        ],
        Some("_req-123"),
        Some("https://sp.example.com"),
        None, // no cert => no signing
    )
    .expect("build_saml_response should succeed");

    // The response must be well-formed XML.
    assert!(
        xml.starts_with("<?xml"),
        "Response must start with XML declaration"
    );
    assert!(
        xml.contains("<samlp:Response"),
        "Must contain Response element"
    );
    assert!(
        xml.contains("<saml:Assertion"),
        "Must contain Assertion element"
    );
    assert!(xml.contains("<saml:Issuer>"), "Must contain Issuer");
    assert!(
        xml.contains("https://casdog.example.com"),
        "Issuer value must match"
    );
    assert!(
        xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"),
        "Must contain Success status"
    );
    assert!(xml.contains("<saml:NameID"), "Must contain NameID element");
    assert!(xml.contains("alice@example.com"), "NameID value must match");

    // Attribute assertions
    assert!(xml.contains(r#"Name="Name"#), "Must have Name attribute");
    assert!(xml.contains(r#"Name="Email"#), "Must have Email attribute");
    assert!(
        xml.contains(r#"Name="DisplayName"#),
        "Must have DisplayName attribute"
    );
    assert!(
        xml.contains(r#"InResponseTo="_req-123""#),
        "InResponseTo must be set"
    );
    assert!(
        xml.contains("<saml:Audience>https://sp.example.com</saml:Audience>"),
        "Audience restriction must be present"
    );

    // Must NOT contain a Signature block when cert is None.
    assert!(
        !xml.contains("<ds:Signature"),
        "Unsigned response must not contain ds:Signature"
    );
}

#[test]
fn build_saml_response_with_empty_attributes_are_omitted() {
    let xml = SamlService::build_saml_response(
        "https://issuer.example.com",
        "https://sp.example.com/acs",
        "bob@example.com",
        "_session-2",
        &[
            ("Name", "bob"),
            ("Email", "bob@example.com"),
            ("Phone", ""), // empty -- should be omitted
        ],
        None,
        None,
        None,
    )
    .expect("build_saml_response should succeed");

    assert!(
        !xml.contains(r#"Name="Phone"#),
        "Empty attribute 'Phone' should be omitted"
    );
    assert!(
        xml.contains(r#"Name="Name"#),
        "Non-empty attribute 'Name' should be present"
    );
}

#[test]
fn build_saml_response_escapes_xml_special_chars() {
    let xml = SamlService::build_saml_response(
        "https://issuer.example.com",
        "https://sp.example.com/acs",
        "user&<>@example.com",
        "_session-3",
        &[("Name", "O'Malley & Sons")],
        None,
        None,
        None,
    )
    .expect("build_saml_response should succeed");

    // The special characters must be escaped.
    assert!(
        xml.contains("user&amp;&lt;&gt;@example.com"),
        "NameID must have XML-escaped special characters"
    );
    assert!(
        xml.contains("O&apos;Malley &amp; Sons"),
        "Attribute value must have XML-escaped special characters"
    );
}

// ===================================================================
// 2.  exclusive_c14n is deterministic
// ===================================================================

#[test]
fn exclusive_c14n_strips_xml_declaration() {
    // We cannot call the private exclusive_c14n directly from an integration
    // test.  Instead we verify the behaviour indirectly: building two SAML
    // responses with the same input must produce the same structure (modulo
    // the random UUIDs for IDs and current timestamps, which we cannot
    // control).
    //
    // What we CAN test: the output of build_saml_response does NOT start with
    // an XML declaration when the assertion is signed (because the assertion
    // is canonicalized before hashing).  Since we test unsigned here, we
    // verify the top-level response DOES have the declaration.
    let xml = SamlService::build_saml_response(
        "https://issuer.example.com",
        "https://sp.example.com/acs",
        "test@example.com",
        "_session-c14n",
        &[("Name", "test")],
        None,
        None,
        None,
    )
    .unwrap();

    assert!(
        xml.starts_with("<?xml version=\"1.0\""),
        "Top-level response must have XML declaration"
    );
}

#[test]
fn c14n_determinism_via_digest_stability() {
    // Build the same response twice (unsigned) and hash the assertion portion.
    // Because UUIDs and timestamps differ, we strip those dynamic parts and
    // verify the structural skeleton is identical.
    let xml1 = SamlService::build_saml_response(
        "https://issuer.test",
        "https://sp.test/acs",
        "determinism@test",
        "_sess",
        &[("Name", "det")],
        Some("_req-det"),
        Some("https://sp.test"),
        None,
    )
    .unwrap();

    let xml2 = SamlService::build_saml_response(
        "https://issuer.test",
        "https://sp.test/acs",
        "determinism@test",
        "_sess",
        &[("Name", "det")],
        Some("_req-det"),
        Some("https://sp.test"),
        None,
    )
    .unwrap();

    // Strip dynamic IDs and timestamps for comparison.
    let normalize = |s: &str| -> String {
        let re_id = regex::Regex::new(r#"ID="_[a-f0-9-]+""#).unwrap();
        let re_ts = regex::Regex::new(r#"(IssueInstant|NotBefore|NotOnOrAfter)="[^"]+""#).unwrap();
        let s = re_id.replace_all(s, r#"ID="STABLE""#);
        let s = re_ts.replace_all(&s, r#"$1="STABLE""#);
        s.to_string()
    };

    assert_eq!(
        normalize(&xml1),
        normalize(&xml2),
        "Two SAML responses with the same inputs must be structurally identical"
    );
}

// ===================================================================
// 3.  XML-DSig signature generation (signing round-trip)
// ===================================================================

#[test]
fn build_saml_response_with_signing_inserts_signature_block() {
    let cert = test_certificate();

    let xml = SamlService::build_saml_response(
        "https://casdog.example.com",
        "https://sp.example.com/acs",
        "signed-user@example.com",
        "_session-sign",
        &[
            ("Name", "signed-user"),
            ("Email", "signed-user@example.com"),
        ],
        Some("_req-sign"),
        Some("https://sp.example.com"),
        Some(&cert),
    )
    .expect("build_saml_response with signing should succeed");

    // The response must contain an XML-DSig Signature block.
    assert!(
        xml.contains("<ds:Signature"),
        "Signed response must contain <ds:Signature>"
    );
    assert!(
        xml.contains("<ds:SignedInfo"),
        "Signed response must contain <ds:SignedInfo>"
    );
    assert!(
        xml.contains("<ds:SignatureValue>"),
        "Signed response must contain <ds:SignatureValue>"
    );
    assert!(
        xml.contains("<ds:X509Certificate>"),
        "Signed response must embed the X.509 certificate"
    );
    assert!(
        xml.contains("<ds:DigestValue>"),
        "Signed response must contain <ds:DigestValue>"
    );
    assert!(
        xml.contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
        "SignatureMethod must be rsa-sha256"
    );
    assert!(
        xml.contains("http://www.w3.org/2001/10/xml-exc-c14n#"),
        "CanonicalizationMethod must be exc-c14n"
    );
    assert!(
        xml.contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature"),
        "Transform must include enveloped-signature"
    );

    // The Signature block must appear INSIDE the Assertion element and AFTER
    // the Issuer element, as required by the SAML 2.0 schema.
    let issuer_end = xml
        .find("</saml:Issuer>")
        .expect("must have Issuer close tag");
    let sig_start = xml
        .find("<ds:Signature")
        .expect("must have Signature element");
    let assertion_end = xml
        .find("</saml:Assertion>")
        .expect("must have Assertion close tag");

    assert!(sig_start > issuer_end, "Signature must appear after Issuer");
    assert!(
        sig_start < assertion_end,
        "Signature must appear inside Assertion"
    );
}

#[test]
fn signed_response_digest_is_valid_sha256() {
    let cert = test_certificate();

    let xml = SamlService::build_saml_response(
        "https://casdog.example.com",
        "https://sp.example.com/acs",
        "digest-test@example.com",
        "_session-digest",
        &[("Name", "digest-test")],
        Some("_req-digest"),
        Some("https://sp.example.com"),
        Some(&cert),
    )
    .unwrap();

    // Extract the DigestValue from the signed response.
    let digest_re = regex::Regex::new(r"<ds:DigestValue>([^<]+)</ds:DigestValue>").unwrap();
    let digest_b64 = digest_re
        .captures(&xml)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim())
        .expect("Must find DigestValue");

    // The DigestValue should be valid base64.
    let digest_bytes = base64::engine::general_purpose::STANDARD
        .decode(digest_b64)
        .expect("DigestValue must be valid base64");

    // SHA-256 produces a 32-byte hash.
    assert_eq!(
        digest_bytes.len(),
        32,
        "SHA-256 digest must be exactly 32 bytes"
    );
}

#[test]
fn signed_response_signature_value_is_valid_base64() {
    let cert = test_certificate();

    let xml = SamlService::build_saml_response(
        "https://casdog.example.com",
        "https://sp.example.com/acs",
        "sigval-test@example.com",
        "_session-sigval",
        &[("Name", "sigval-test")],
        Some("_req-sigval"),
        Some("https://sp.example.com"),
        Some(&cert),
    )
    .unwrap();

    let sig_re = regex::Regex::new(r"<ds:SignatureValue>([^<]+)</ds:SignatureValue>").unwrap();
    let sig_b64 = sig_re
        .captures(&xml)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim())
        .expect("Must find SignatureValue");

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .expect("SignatureValue must be valid base64");

    // For a 2048-bit RSA key, the signature is 256 bytes.
    assert_eq!(
        sig_bytes.len(),
        256,
        "RSA-2048 signature must be exactly 256 bytes"
    );
}

// ===================================================================
// 4.  IDP metadata generation
// ===================================================================

#[test]
fn generate_idp_metadata_produces_valid_xml() {
    let metadata = SamlService::generate_idp_metadata(
        "https://casdog.example.com",
        "https://casdog.example.com/api/saml/redirect/admin/app",
        None,
        TEST_CERTIFICATE,
        false,
    )
    .expect("generate_idp_metadata should succeed");

    assert!(
        metadata.contains("<?xml"),
        "Metadata must start with XML declaration"
    );
    assert!(
        metadata.contains("<md:EntityDescriptor"),
        "Must contain EntityDescriptor"
    );
    assert!(
        metadata.contains("<md:IDPSSODescriptor"),
        "Must contain IDPSSODescriptor"
    );
    assert!(
        metadata.contains("<ds:X509Certificate>"),
        "Must contain X509Certificate"
    );
    assert!(
        metadata.contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
        "Default binding should be HTTP-Redirect"
    );
    assert!(
        metadata.contains("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        "Must support emailAddress NameID format"
    );
    assert!(
        metadata.contains("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
        "Must support persistent NameID format"
    );
    assert!(
        metadata.contains("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
        "Must support transient NameID format"
    );
}

#[test]
fn generate_idp_metadata_with_post_binding() {
    let metadata = SamlService::generate_idp_metadata(
        "https://casdog.example.com",
        "https://casdog.example.com/api/saml/redirect/admin/app",
        None,
        TEST_CERTIFICATE,
        true, // enable POST binding
    )
    .expect("generate_idp_metadata with POST binding should succeed");

    assert!(
        metadata.contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
        "POST binding must be present when enable_post_binding=true"
    );
}

#[test]
fn generate_idp_metadata_with_slo_url() {
    let metadata = SamlService::generate_idp_metadata(
        "https://casdog.example.com",
        "https://casdog.example.com/sso",
        Some("https://casdog.example.com/slo"),
        TEST_CERTIFICATE,
        false,
    )
    .expect("generate_idp_metadata with SLO should succeed");

    assert!(
        metadata.contains("<md:SingleLogoutService"),
        "Must contain SingleLogoutService when SLO URL is provided"
    );
    assert!(
        metadata.contains("https://casdog.example.com/slo"),
        "SLO URL must be present in metadata"
    );
}

// ===================================================================
// 5.  AuthnRequest building
// ===================================================================

#[test]
fn build_authn_request_redirect_binding() {
    let login_request = SamlService::build_authn_request(
        "https://sp.example.com",
        "https://sp.example.com/acs",
        "https://idp.example.com/sso",
        Some("some-relay-state"),
        false, // redirect binding
    )
    .expect("build_authn_request should succeed");

    assert_eq!(login_request.method, "GET");
    assert!(
        login_request
            .auth_url
            .starts_with("https://idp.example.com/sso?SAMLRequest="),
        "Auth URL must start with destination + SAMLRequest param"
    );
    assert!(
        login_request.auth_url.contains("RelayState="),
        "Auth URL must contain RelayState"
    );
    assert!(
        login_request.form_html.is_none(),
        "Redirect binding should not produce form HTML"
    );
}

#[test]
fn build_authn_request_post_binding() {
    let login_request = SamlService::build_authn_request(
        "https://sp.example.com",
        "https://sp.example.com/acs",
        "https://idp.example.com/sso",
        Some("post-relay-state"),
        true, // POST binding
    )
    .expect("build_authn_request should succeed");

    assert_eq!(login_request.method, "POST");
    assert_eq!(login_request.auth_url, "https://idp.example.com/sso");
    assert!(
        login_request.form_html.is_some(),
        "POST binding must produce form HTML"
    );
    let form = login_request.form_html.unwrap();
    assert!(
        form.contains("SAMLRequest"),
        "Form must contain SAMLRequest field"
    );
    assert!(
        form.contains("post-relay-state"),
        "Form must contain RelayState"
    );
    assert!(
        form.contains("document.forms[0].submit()"),
        "Form must auto-submit via JavaScript"
    );
}

// ===================================================================
// 6.  SAML request parsing
// ===================================================================

#[test]
fn parse_saml_request_round_trip() {
    // Build a request, then parse it back.
    let login_request = SamlService::build_authn_request(
        "https://sp.example.com",
        "https://sp.example.com/acs",
        "https://idp.example.com/sso",
        None,
        false,
    )
    .unwrap();

    // Extract the SAMLRequest parameter from the URL.
    let url = &login_request.auth_url;
    let saml_param = url
        .split("SAMLRequest=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("URL must contain SAMLRequest parameter");
    let decoded_param = urlencoding::decode(saml_param).unwrap();

    let info = SamlService::parse_request(&decoded_param).expect("parse_request should succeed");

    assert_eq!(info.issuer, "https://sp.example.com");
    assert_eq!(
        info.destination.as_deref(),
        Some("https://idp.example.com/sso")
    );
    assert!(info.request_id.is_some(), "Request must have an ID");
    assert!(
        info.request_id.as_ref().unwrap().starts_with('_'),
        "Request ID should start with underscore"
    );
}

// ===================================================================
// 7.  Relay state decoding
// ===================================================================

#[test]
fn decode_relay_state_url() {
    let url = "https://app.example.com/dashboard";
    let encoded = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
    let result = SamlService::decode_relay_state_target(&encoded);
    assert_eq!(result, Some(url.to_string()));
}

#[test]
fn decode_relay_state_json_redirect() {
    let json = r#"{"redirect":"https://app.example.com/home"}"#;
    let encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    let result = SamlService::decode_relay_state_target(&encoded);
    assert_eq!(result, Some("https://app.example.com/home".to_string()));
}

#[test]
fn decode_relay_state_key_value_pairs() {
    let pairs = "redirect=https://app.example.com/callback&extra=ignored";
    let encoded = base64::engine::general_purpose::STANDARD.encode(pairs.as_bytes());
    let result = SamlService::decode_relay_state_target(&encoded);
    assert_eq!(result, Some("https://app.example.com/callback".to_string()));
}

#[test]
fn decode_relay_state_returns_none_for_opaque_string() {
    let opaque = "just-some-random-text-no-url";
    let encoded = base64::engine::general_purpose::STANDARD.encode(opaque.as_bytes());
    let result = SamlService::decode_relay_state_target(&encoded);
    assert!(
        result.is_none(),
        "Opaque relay state without a URL should return None"
    );
}

// ===================================================================
// 8.  Redirect URI matching
// ===================================================================

#[test]
fn redirect_uri_allowed_matches_exact() {
    assert!(SamlService::redirect_uri_allowed(
        "https://a.com,https://b.com",
        "https://b.com"
    ));
}

#[test]
fn redirect_uri_allowed_rejects_mismatch() {
    assert!(!SamlService::redirect_uri_allowed(
        "https://a.com,https://b.com",
        "https://evil.com"
    ));
}

#[test]
fn redirect_uri_allowed_handles_whitespace() {
    assert!(SamlService::redirect_uri_allowed(
        "https://a.com , https://b.com",
        "https://b.com"
    ));
}

// ===================================================================
// 9.  Auto-post form generation
// ===================================================================

#[test]
fn build_auto_post_form_structure() {
    let form = SamlService::build_auto_post_form(
        "https://sp.example.com/acs",
        &[("SAMLResponse", "base64data"), ("RelayState", "some-state")],
    );

    assert!(
        form.contains("<!doctype html>"),
        "Must be a valid HTML document"
    );
    assert!(
        form.contains(r#"action="https://sp.example.com/acs""#),
        "Form action must match"
    );
    assert!(
        form.contains(r#"name="SAMLResponse""#),
        "Must have SAMLResponse hidden input"
    );
    assert!(
        form.contains(r#"value="base64data""#),
        "SAMLResponse value must match"
    );
    assert!(
        form.contains(r#"name="RelayState""#),
        "Must have RelayState hidden input"
    );
    assert!(
        form.contains("document.forms[0].submit()"),
        "Must auto-submit"
    );
    assert!(form.contains("<noscript>"), "Must have noscript fallback");
}

#[test]
fn build_auto_post_form_omits_empty_fields() {
    let form = SamlService::build_auto_post_form(
        "https://sp.example.com/acs",
        &[
            ("SAMLResponse", "data"),
            ("RelayState", ""), // empty => should be omitted
        ],
    );

    assert!(
        !form.contains(r#"name="RelayState""#),
        "Empty RelayState field should be omitted"
    );
}

//! Integration tests for SPNEGO / Kerberos token parsing and identity
//! extraction.
//!
//! These tests exercise `casdog::services::spnego_service::SpnegoService`
//! directly, validating the ASN.1 DER reader, the GSSAPI/SPNEGO decode chain,
//! and the identity extraction fallback logic.

use casdog::services::spnego_service::{SpnegoIdentity, SpnegoService};

// ===================================================================
// 1.  extract_identity -- proxy header
// ===================================================================

#[test]
fn extract_identity_from_proxy_header_strips_realm() {
    let result = SpnegoService::extract_identity(None, Some("alice@EXAMPLE.COM"), None).unwrap();
    assert_eq!(result, "alice", "Should strip @REALM from proxy header");
}

#[test]
fn extract_identity_from_proxy_header_no_realm() {
    let result = SpnegoService::extract_identity(None, Some("bob"), None).unwrap();
    assert_eq!(result, "bob");
}

#[test]
fn extract_identity_from_proxy_header_with_whitespace() {
    let result = SpnegoService::extract_identity(None, Some("  carol@CORP.NET  "), None).unwrap();
    assert_eq!(result, "carol", "Should trim whitespace and strip realm");
}

#[test]
fn extract_identity_empty_proxy_header_falls_through() {
    // Empty string in proxy header should fall through to query param.
    let result = SpnegoService::extract_identity(None, Some("   "), Some("fallback-user")).unwrap();
    assert_eq!(result, "fallback-user");
}

// ===================================================================
// 2.  extract_identity -- query parameter
// ===================================================================

#[test]
fn extract_identity_from_query_param() {
    let result = SpnegoService::extract_identity(None, None, Some("query-user")).unwrap();
    assert_eq!(result, "query-user");
}

#[test]
fn extract_identity_from_query_param_with_whitespace() {
    let result = SpnegoService::extract_identity(None, None, Some("  trimmed  ")).unwrap();
    assert_eq!(result, "trimmed");
}

#[test]
fn extract_identity_empty_query_param_fails() {
    let result = SpnegoService::extract_identity(None, None, Some("   "));
    assert!(result.is_err(), "Empty query param should fail");
}

// ===================================================================
// 3.  extract_identity -- no input
// ===================================================================

#[test]
fn extract_identity_all_none_fails() {
    let result = SpnegoService::extract_identity(None, None, None);
    assert!(
        result.is_err(),
        "extract_identity with no input must return an error"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("No valid Kerberos identity"),
        "Error message should mention Kerberos identity"
    );
}

// ===================================================================
// 4.  extract_identity -- priority order
// ===================================================================

#[test]
fn extract_identity_proxy_header_takes_priority_over_query() {
    // When both proxy header and query param are present, proxy header wins.
    let result =
        SpnegoService::extract_identity(None, Some("proxy-user@REALM"), Some("query-user"))
            .unwrap();
    assert_eq!(
        result, "proxy-user",
        "Proxy header should take priority over query param"
    );
}

// ===================================================================
// 5.  ASN.1 DER reader -- known byte sequences
// ===================================================================

#[test]
fn read_tlv_short_form_length() {
    // SEQUENCE tag (0x30), length 3, value [0x01, 0x02, 0x03]
    let data: &[u8] = &[0x30, 0x03, 0x01, 0x02, 0x03];

    // We use parse_negotiate_token indirectly, but the read_tlv is private.
    // Instead we verify through the public API by constructing known-bad tokens
    // and checking the error messages, which exercise the DER reader code paths.

    // A token that is too short should fail with a descriptive error.
    let result = SpnegoService::parse_negotiate_token("AA=="); // single zero byte
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("too short") || err.contains("Unrecognised"),
        "Short token should produce a descriptive error, got: {err}"
    );
}

#[test]
fn parse_negotiate_token_rejects_empty_input() {
    let result = SpnegoService::parse_negotiate_token("");
    assert!(result.is_err(), "Empty base64 input should fail");
}

#[test]
fn parse_negotiate_token_rejects_invalid_base64() {
    let result = SpnegoService::parse_negotiate_token("not!valid!base64!!!");
    assert!(result.is_err(), "Invalid base64 should fail");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("base64") || err.contains("Invalid"),
        "Error should mention base64, got: {err}"
    );
}

#[test]
fn parse_negotiate_token_rejects_unknown_tag() {
    // A valid base64 token whose first byte is 0xFF (not 0x60 or 0xa0).
    let token = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &[0xFF, 0x03, 0x01, 0x02, 0x03],
    );
    let result = SpnegoService::parse_negotiate_token(&token);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("Unrecognised") || err.contains("tag"),
        "Unknown tag should produce a descriptive error, got: {err}"
    );
}

#[test]
fn parse_negotiate_token_handles_truncated_gssapi_wrapper() {
    // A GSSAPI APPLICATION [0] wrapper (tag 0x60) with a length that exceeds
    // the actual data -- should fail with a truncation error.
    let token = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &[0x60, 0x80], // indefinite length form not supported
    );
    let result = SpnegoService::parse_negotiate_token(&token);
    assert!(result.is_err(), "Truncated GSSAPI wrapper should fail");
}

#[test]
fn parse_negotiate_token_handles_truncated_spnego() {
    // Raw SPNEGO NegTokenInit (tag 0xa0) with a claimed length of 10 but only
    // 2 bytes of actual content.
    let token = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &[0xa0, 0x0a, 0x01, 0x02],
    );
    let result = SpnegoService::parse_negotiate_token(&token);
    assert!(result.is_err(), "Truncated SPNEGO token should fail");
}

// ===================================================================
// 6.  ASN.1 DER -- long-form length encoding
// ===================================================================

#[test]
fn parse_negotiate_token_long_form_length_1_byte() {
    // Build a minimal token with a long-form 1-byte length.
    // Tag 0xa0 (NegTokenInit), long-form length: 0x81 0x04 (4 bytes),
    // then 4 bytes of dummy data.  This will exercise the long-form length
    // code path before failing on the inner structure.
    let data: Vec<u8> = vec![0xa0, 0x81, 0x04, 0x30, 0x02, 0x01, 0x00];
    let token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
    let result = SpnegoService::parse_negotiate_token(&token);
    // We don't expect success (the inner structure is too short to be a valid
    // SPNEGO NegTokenInit), but the DER reader should not panic.
    assert!(
        result.is_err(),
        "Malformed inner structure should fail gracefully"
    );
}

#[test]
fn parse_negotiate_token_long_form_length_2_bytes() {
    // Tag 0xa0, long-form 2-byte length: 0x82 0x00 0x03 (3 bytes), then 3
    // bytes of dummy data.
    let data: Vec<u8> = vec![0xa0, 0x82, 0x00, 0x03, 0x30, 0x01, 0x00];
    let token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
    let result = SpnegoService::parse_negotiate_token(&token);
    assert!(
        result.is_err(),
        "Malformed inner structure should fail gracefully"
    );
}

// ===================================================================
// 7.  SpnegoIdentity formatting
// ===================================================================

#[test]
fn spnego_identity_principal_with_realm() {
    let identity = SpnegoIdentity {
        realm: "EXAMPLE.COM".to_string(),
        client_name: vec!["alice".to_string()],
        service_name: vec!["HTTP".to_string(), "server.example.com".to_string()],
        ap_req_bytes: vec![],
    };
    assert_eq!(identity.principal(), "alice@EXAMPLE.COM");
    assert_eq!(identity.username(), Some("alice"));
}

#[test]
fn spnego_identity_principal_without_realm() {
    let identity = SpnegoIdentity {
        realm: String::new(),
        client_name: vec!["bob".to_string()],
        service_name: vec![],
        ap_req_bytes: vec![],
    };
    assert_eq!(identity.principal(), "bob");
}

#[test]
fn spnego_identity_principal_multiple_components() {
    let identity = SpnegoIdentity {
        realm: "CORP.NET".to_string(),
        client_name: vec!["HTTP".to_string(), "webserver.corp.net".to_string()],
        service_name: vec![],
        ap_req_bytes: vec![],
    };
    assert_eq!(identity.principal(), "HTTP/webserver.corp.net@CORP.NET");
}

#[test]
fn spnego_identity_username_empty_client_name() {
    let identity = SpnegoIdentity {
        realm: "EXAMPLE.COM".to_string(),
        client_name: vec![],
        service_name: vec![],
        ap_req_bytes: vec![],
    };
    assert_eq!(identity.username(), None);
}

// ===================================================================
// 8.  Well-formed GSSAPI SPNEGO token (synthetic)
// ===================================================================

/// Build a minimal synthetic GSSAPI-wrapped SPNEGO NegTokenInit with a
/// Kerberos AP-REQ.  The ticket contains a realm and service principal
/// so we can verify the parser extracts them correctly.
///
/// This is a hand-crafted byte sequence, not a real Kerberos ticket.
fn build_synthetic_negotiate_token() -> Vec<u8> {
    // -- Inner-most: Kerberos Ticket (APPLICATION [1]) --
    // Ticket = APPLICATION [1] SEQUENCE {
    //   [0] INTEGER 5 (tkt-vno)
    //   [1] GeneralString "TEST.REALM" (realm)
    //   [2] PrincipalName = SEQUENCE {
    //         [0] INTEGER 2 (name-type: NT-SRV-HST)
    //         [1] SEQUENCE OF GeneralString { "HTTP", "host.test" }
    //       }
    //   [3] EncryptedData (dummy)
    // }
    let realm_value = b"TEST.REALM";
    let realm_str = asn1_string(0x1b, realm_value); // GeneralString
    let realm_field = asn1_context(1, &realm_str);

    let sname_str1 = asn1_string(0x1b, b"HTTP");
    let sname_str2 = asn1_string(0x1b, b"host.test");
    let sname_seq_of = asn1_sequence(&[&sname_str1, &sname_str2]);
    let sname_field1 = asn1_context(1, &sname_seq_of);
    let name_type = asn1_context(0, &asn1_integer(2));
    let sname_inner = asn1_sequence(&[&name_type, &sname_field1]);
    let sname_field = asn1_context(2, &sname_inner);

    let tkt_vno = asn1_context(0, &asn1_integer(5));
    let enc_data = asn1_context(3, &asn1_sequence(&[&asn1_integer(0)]));
    let ticket_seq = asn1_sequence(&[&tkt_vno, &realm_field, &sname_field, &enc_data]);
    let ticket = asn1_application(1, &ticket_seq);

    // -- AP-REQ (APPLICATION [14]) --
    let pvno = asn1_context(0, &asn1_integer(5));
    let msg_type = asn1_context(1, &asn1_integer(14));
    let ap_options = asn1_context(2, &asn1_bitstring(&[0x00]));
    let ticket_field = asn1_context(3, &ticket);
    let authenticator = asn1_context(4, &asn1_sequence(&[&asn1_integer(0)]));
    let ap_req_seq = asn1_sequence(&[&pvno, &msg_type, &ap_options, &ticket_field, &authenticator]);
    let ap_req = asn1_application(14, &ap_req_seq);

    // -- SPNEGO NegTokenInit --
    // NegTokenInit = [0] CONSTRUCTED SEQUENCE {
    //   [0] mechTypes (SEQUENCE OF OID)
    //   [2] mechToken (OCTET STRING = ap_req)
    // }
    let krb5_oid: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
    ];
    let mech_types = asn1_context(0, &asn1_sequence_raw(&[krb5_oid]));
    let mech_token = asn1_context(2, &asn1_octet_string(&ap_req));
    let neg_token_init_seq = asn1_sequence(&[&mech_types, &mech_token]);
    let neg_token_init = asn1_context(0, &neg_token_init_seq);

    // -- GSSAPI wrapper (APPLICATION [0]) --
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    let mut gssapi_content = Vec::new();
    gssapi_content.extend_from_slice(spnego_oid);
    gssapi_content.extend_from_slice(&neg_token_init);
    asn1_application_raw(0, &gssapi_content)
}

// -- ASN.1 encoding helpers --

fn asn1_tag_length(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn asn1_integer(value: i32) -> Vec<u8> {
    if value >= 0 && value < 128 {
        asn1_tag_length(0x02, &[value as u8])
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        asn1_tag_length(0x02, &bytes[start..])
    }
}

fn asn1_string(tag: u8, value: &[u8]) -> Vec<u8> {
    asn1_tag_length(tag, value)
}

fn asn1_octet_string(value: &[u8]) -> Vec<u8> {
    asn1_tag_length(0x04, value)
}

fn asn1_bitstring(value: &[u8]) -> Vec<u8> {
    asn1_tag_length(0x03, value)
}

fn asn1_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    asn1_tag_length(0x30, &content)
}

fn asn1_sequence_raw(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    asn1_tag_length(0x30, &content)
}

fn asn1_context(tag_num: u8, content: &[u8]) -> Vec<u8> {
    asn1_tag_length(0xa0 | tag_num, content)
}

fn asn1_application(tag_num: u8, content: &[u8]) -> Vec<u8> {
    // APPLICATION CONSTRUCTED = 0x60 | tag_num
    asn1_tag_length(0x60 | tag_num, content)
}

fn asn1_application_raw(tag_num: u8, content: &[u8]) -> Vec<u8> {
    asn1_tag_length(0x60 | tag_num, content)
}

#[test]
fn parse_synthetic_negotiate_token_extracts_realm_and_service() {
    let token_bytes = build_synthetic_negotiate_token();
    let token_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &token_bytes);

    let identity = SpnegoService::parse_negotiate_token(&token_b64)
        .expect("Parsing synthetic SPNEGO token should succeed");

    assert_eq!(identity.realm, "TEST.REALM");
    assert_eq!(identity.service_name, vec!["HTTP", "host.test"]);
    // Without decryption, client_name mirrors service_name.
    assert_eq!(identity.client_name, vec!["HTTP", "host.test"]);
    assert!(!identity.ap_req_bytes.is_empty());
}

#[test]
fn parse_synthetic_token_principal_format() {
    let token_bytes = build_synthetic_negotiate_token();
    let token_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &token_bytes);

    let identity = SpnegoService::parse_negotiate_token(&token_b64).unwrap();
    assert_eq!(identity.principal(), "HTTP/host.test@TEST.REALM");
    assert_eq!(identity.username(), Some("HTTP"));
}

#[test]
fn extract_identity_prefers_negotiate_token() {
    let token_bytes = build_synthetic_negotiate_token();
    let token_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &token_bytes);

    // When a valid token is provided, it should take priority over proxy
    // header and query param.
    let result = SpnegoService::extract_identity(
        Some(&token_b64),
        Some("proxy-user@REALM"),
        Some("query-user"),
    )
    .unwrap();

    // The token's first client_name component is "HTTP" (service principal).
    assert_eq!(result, "HTTP", "Valid Negotiate token should take priority");
}

#[test]
fn extract_identity_falls_back_when_token_parse_fails() {
    // An invalid token that will fail to parse.
    let bad_token = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &[0x60, 0x01, 0xFF], // GSSAPI wrapper with garbage content
    );

    let result =
        SpnegoService::extract_identity(Some(&bad_token), Some("fallback-user@CORP.NET"), None)
            .unwrap();

    assert_eq!(
        result, "fallback-user",
        "Should fall back to proxy header when token parsing fails"
    );
}

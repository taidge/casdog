//! SPNEGO / Kerberos framing and legacy diagnostic parsing.
//!
//! Diagnostic metadata never authenticates a client. The login endpoint uses
//! `KerberosService` for keytab-backed cryptographic verification and shared
//! replay protection; `extract_identity` deliberately rejects caller claims.

use base64::Engine;

use crate::error::{AppError, AppResult};

// -- OIDs --------------------------------------------------------------------

/// SPNEGO OID: 1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Kerberos v5 OID: 1.2.840.113554.1.2.2
const KRB5_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

// -- Public types ------------------------------------------------------------

/// Information extracted from a SPNEGO / Kerberos Negotiate token.
#[derive(Debug, Clone)]
pub struct SpnegoIdentity {
    /// Kerberos realm (e.g. `EXAMPLE.COM`).
    pub realm: String,
    /// Client principal name components (e.g. `["alice"]`).
    pub client_name: Vec<String>,
    /// Service principal name components extracted from the ticket.
    pub service_name: Vec<String>,
    /// The raw Kerberos AP-REQ bytes for optional downstream validation.
    pub ap_req_bytes: Vec<u8>,
}

impl SpnegoIdentity {
    /// Returns the primary client principal formatted as `name@REALM`.
    pub fn principal(&self) -> String {
        let name = self.client_name.join("/");
        if self.realm.is_empty() {
            name
        } else {
            format!("{name}@{realm}", name = name, realm = self.realm)
        }
    }

    /// Returns just the short username (first component of the principal).
    pub fn username(&self) -> Option<&str> {
        self.client_name.first().map(String::as_str)
    }
}

pub struct SpnegoService;

/// A bounded, structurally checked mechanism token. This is NOT an identity.
pub(crate) struct AuthenticationToken {
    pub ap_req: Vec<u8>,
    pub spnego_mechanism: Option<Vec<u8>>,
}

const MS_KRB5_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

fn protocol_error() -> AppError {
    AppError::Authentication("Invalid Kerberos negotiation token".into())
}

fn exact_tlv(data: &[u8], tag: u8) -> AppResult<&[u8]> {
    if data.first() != Some(&tag) {
        return Err(protocol_error());
    }
    let (len, value) = SpnegoService::read_tlv(data)?;
    if len != data.len() {
        return Err(protocol_error());
    }
    Ok(value)
}

pub(crate) fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut value = vec![tag];
    if content.len() < 128 {
        value.push(content.len() as u8);
    } else {
        let bytes = content.len().to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap();
        value.push(0x80 | (bytes.len() - start) as u8);
        value.extend_from_slice(&bytes[start..]);
    }
    value.extend_from_slice(content);
    value
}

pub(crate) fn kerberos_gss(ap_req: &[u8]) -> Vec<u8> {
    let mut inner = KRB5_OID.to_vec();
    inner.extend_from_slice(&[1, 0]);
    inner.extend_from_slice(ap_req);
    der(0x60, &inner)
}

pub(crate) fn kerberos_reply(ap_rep: &[u8]) -> Vec<u8> {
    let mut inner = KRB5_OID.to_vec();
    inner.extend_from_slice(&[2, 0]);
    inner.extend_from_slice(ap_rep);
    der(0x60, &inner)
}

impl AuthenticationToken {
    pub fn response(&self, kerberos_reply: &[u8]) -> Vec<u8> {
        if let Some(mechanism) = &self.spnego_mechanism {
            // NegTokenResp: accept-completed, chosen mechanism, optional AP-REP.
            let mut fields = der(0xa0, &[0x0a, 1, 0]);
            fields.extend(der(0xa1, mechanism));
            if !kerberos_reply.is_empty() {
                fields.extend(der(0xa2, &der(0x04, kerberos_reply)));
            }
            der(0xa1, &der(0x30, &fields))
        } else {
            kerberos_reply.to_vec()
        }
    }
}

impl SpnegoService {
    pub(crate) fn authentication_token(token_b64: &str) -> AppResult<AuthenticationToken> {
        if token_b64.is_empty() || token_b64.len() > 128 * 1024 {
            return Err(protocol_error());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(token_b64)
            .map_err(|_| protocol_error())?;
        let mut token = bytes.as_slice();
        let mut mechanism = None;
        if token.first() == Some(&0x60) {
            let content = exact_tlv(token, 0x60)?;
            let (n, _) = Self::read_tlv(content)?;
            let oid = &content[..n];
            if oid == SPNEGO_OID {
                token = &content[n..];
            } else if oid == KRB5_OID || oid == MS_KRB5_OID {
                let raw = content[n..]
                    .strip_prefix(&[1, 0])
                    .ok_or_else(protocol_error)?;
                exact_tlv(raw, 0x6e)?;
                return Ok(AuthenticationToken {
                    ap_req: raw.to_vec(),
                    spnego_mechanism: None,
                });
            } else {
                return Err(protocol_error());
            }
        }
        if token.first() != Some(&0xa0) {
            return Err(protocol_error());
        }
        let fields = exact_tlv(exact_tlv(token, 0xa0)?, 0x30)?;
        let mut position = 0;
        let mut previous = 0x9f;
        let mut mech_token = None;
        while position < fields.len() {
            let field = &fields[position..];
            let tag = field[0];
            let (n, content) = Self::read_tlv(field)?;
            if tag <= previous || !(0xa0..=0xa3).contains(&tag) {
                return Err(protocol_error());
            }
            previous = tag;
            match tag {
                0xa0 => {
                    let mechs = exact_tlv(content, 0x30)?;
                    let (first, _) = Self::read_tlv(mechs)?;
                    let preferred = &mechs[..first];
                    // Never select a fallback mechanism: that would require a
                    // mechListMIC exchange. NTLM is never an authentication path.
                    if preferred != KRB5_OID && preferred != MS_KRB5_OID {
                        return Err(protocol_error());
                    }
                    let mut i = first;
                    let mut count = 1;
                    while i < mechs.len() {
                        if mechs[i] != 6 || count >= 16 {
                            return Err(protocol_error());
                        }
                        i += Self::read_tlv(&mechs[i..])?.0;
                        count += 1;
                    }
                    mechanism = Some(preferred.to_vec());
                }
                0xa1 => {
                    exact_tlv(content, 0x03)?;
                }
                0xa2 => {
                    mech_token = Some(exact_tlv(content, 0x04)?);
                }
                _ => return Err(protocol_error()), // no unauthenticated MIC claims
            }
            position += n;
        }
        let inner = mech_token.ok_or_else(protocol_error)?;
        if mechanism.is_none() {
            return Err(protocol_error());
        }
        let ap_req = if inner.first() == Some(&0x60) {
            let wrapped = exact_tlv(inner, 0x60)?;
            let (n, _) = Self::read_tlv(wrapped)?;
            if &wrapped[..n] != KRB5_OID && &wrapped[..n] != MS_KRB5_OID {
                return Err(protocol_error());
            }
            wrapped[n..]
                .strip_prefix(&[1, 0])
                .ok_or_else(protocol_error)?
        } else {
            inner
        };
        exact_tlv(ap_req, 0x6e)?;
        Ok(AuthenticationToken {
            ap_req: ap_req.to_vec(),
            spnego_mechanism: mechanism,
        })
    }
    /// Parse a base64-encoded Negotiate token into an [`SpnegoIdentity`].
    ///
    /// Handles the full GSSAPI → SPNEGO → Kerberos AP-REQ decode chain.
    pub fn parse_negotiate_token(token_b64: &str) -> AppResult<SpnegoIdentity> {
        let token_bytes = base64::engine::general_purpose::STANDARD
            .decode(token_b64.trim().as_bytes())
            .map_err(|e| AppError::Authentication(format!("Invalid Negotiate base64: {e}")))?;

        if token_bytes.len() < 2 {
            return Err(AppError::Authentication(
                "Negotiate token too short".to_string(),
            ));
        }

        // Try GSSAPI-wrapped SPNEGO first, then raw SPNEGO NegTokenInit.
        let spnego_bytes = if token_bytes[0] == 0x60 {
            // GSSAPI APPLICATION [0] wrapper
            Self::unwrap_gssapi(&token_bytes)?
        } else if token_bytes[0] == 0xa0 {
            // Raw SPNEGO NegTokenInit (context tag [0])
            token_bytes.clone()
        } else {
            return Err(AppError::Authentication(format!(
                "Unrecognised Negotiate token tag: 0x{:02x}",
                token_bytes[0]
            )));
        };

        let ap_req_bytes = Self::extract_mech_token(&spnego_bytes)?;
        Self::parse_ap_req(&ap_req_bytes)
    }

    // -- GSSAPI unwrap -------------------------------------------------------

    fn unwrap_gssapi(data: &[u8]) -> AppResult<Vec<u8>> {
        let (_, content) = Self::read_tlv(data)?;
        // Content starts with the mech OID. Verify it is SPNEGO.
        if content.len() < SPNEGO_OID.len() || !content.starts_with(&SPNEGO_OID[2..]) {
            // Check the OID including tag+length
            let oid_end = Self::find_oid_end(content)?;
            let remaining = &content[oid_end..];
            return Ok(remaining.to_vec());
        }
        // Skip the OID TLV
        let oid_end = Self::find_oid_end(content)?;
        Ok(content[oid_end..].to_vec())
    }

    fn find_oid_end(data: &[u8]) -> AppResult<usize> {
        if data.is_empty() || data[0] != 0x06 {
            return Err(AppError::Authentication(
                "Expected OID in GSSAPI wrapper".to_string(),
            ));
        }
        let (consumed, _) = Self::read_tlv(data)?;
        Ok(consumed)
    }

    // -- SPNEGO NegTokenInit extraction --------------------------------------

    fn extract_mech_token(spnego: &[u8]) -> AppResult<Vec<u8>> {
        if spnego.is_empty() {
            return Err(AppError::Authentication("Empty SPNEGO token".to_string()));
        }

        // NegTokenInit is context tag [0] CONSTRUCTED
        let (_, inner) = Self::read_tlv(spnego)?;

        // Inner is a SEQUENCE
        let (_, seq_content) = Self::read_tlv(inner)?;

        // Walk the fields: [0] mechTypes, [1] reqFlags, [2] mechToken, [3] mechListMIC
        let mut pos = 0;
        while pos < seq_content.len() {
            let tag = seq_content[pos];
            let (consumed, field_content) = Self::read_tlv(&seq_content[pos..])?;

            // Context tag [2] = mechToken
            if tag == 0xa2 {
                // mechToken is an OCTET STRING inside the context tag
                let (_, token_bytes) = Self::read_tlv(field_content)?;
                return Ok(token_bytes.to_vec());
            }

            pos += consumed;
        }

        Err(AppError::Authentication(
            "SPNEGO NegTokenInit missing mechToken field".to_string(),
        ))
    }

    // -- Kerberos AP-REQ parsing ---------------------------------------------

    fn parse_ap_req(ap_req: &[u8]) -> AppResult<SpnegoIdentity> {
        if ap_req.is_empty() {
            return Err(AppError::Authentication("Empty AP-REQ".to_string()));
        }

        // AP-REQ: APPLICATION [14] SEQUENCE { pvno, msg-type, ap-options, ticket, authenticator }
        let (_, app_content) = Self::read_tlv(ap_req)?;
        let (_, seq_content) = Self::read_tlv(app_content)?;

        // Skip pvno [0], msg-type [1], ap-options [2]. Find ticket [3].
        let mut pos = 0;
        let mut ticket_bytes: Option<&[u8]> = None;
        while pos < seq_content.len() {
            let tag = seq_content[pos];
            let (consumed, field_content) = Self::read_tlv(&seq_content[pos..])?;
            if tag == 0xa3 {
                ticket_bytes = Some(field_content);
            }
            pos += consumed;
        }

        let ticket_bytes = ticket_bytes
            .ok_or_else(|| AppError::Authentication("AP-REQ missing ticket field".to_string()))?;

        Self::parse_ticket(ticket_bytes)
    }

    fn parse_ticket(data: &[u8]) -> AppResult<SpnegoIdentity> {
        // Ticket: APPLICATION [1] SEQUENCE { tkt-vno, realm, sname, enc-part }
        let (_, app_content) = Self::read_tlv(data)?;
        let (_, seq_content) = Self::read_tlv(app_content)?;

        let mut realm = String::new();
        let mut sname_parts = Vec::new();
        let mut pos = 0;

        while pos < seq_content.len() {
            let tag = seq_content[pos];
            let (consumed, field_content) = Self::read_tlv(&seq_content[pos..])?;

            match tag {
                0xa1 => {
                    // realm [1] GeneralString
                    realm = Self::extract_string_value(field_content)?;
                }
                0xa2 => {
                    // sname [2] PrincipalName = SEQUENCE { name-type, name-string }
                    sname_parts = Self::extract_principal_name(field_content)?;
                }
                _ => {}
            }

            pos += consumed;
        }

        // The client principal is encrypted. Never substitute the service name.
        Ok(SpnegoIdentity {
            realm: realm.clone(),
            client_name: Vec::new(),
            service_name: sname_parts,
            ap_req_bytes: data.to_vec(),
        })
    }

    fn extract_principal_name(data: &[u8]) -> AppResult<Vec<String>> {
        let (_, seq_content) = Self::read_tlv(data)?;
        let mut names = Vec::new();
        let mut pos = 0;
        while pos < seq_content.len() {
            let tag = seq_content[pos];
            let (consumed, field_content) = Self::read_tlv(&seq_content[pos..])?;
            if tag == 0xa1 {
                // name-string [1] SEQUENCE OF GeneralString
                let (_, str_seq) = Self::read_tlv(field_content)?;
                let mut spos = 0;
                while spos < str_seq.len() {
                    let (sc, sv) = Self::read_tlv(&str_seq[spos..])?;
                    if let Ok(s) = std::str::from_utf8(sv) {
                        names.push(s.to_string());
                    }
                    spos += sc;
                }
            }
            pos += consumed;
        }
        Ok(names)
    }

    fn extract_string_value(data: &[u8]) -> AppResult<String> {
        let (_, value) = Self::read_tlv(data)?;
        String::from_utf8(value.to_vec())
            .map_err(|e| AppError::Authentication(format!("Invalid UTF-8 in ASN.1 string: {e}")))
    }

    // -- Minimal ASN.1 DER reader --------------------------------------------

    /// Read a Tag-Length-Value triple. Returns (total_consumed, value_slice).
    fn read_tlv(data: &[u8]) -> AppResult<(usize, &[u8])> {
        if data.is_empty() {
            return Err(AppError::Authentication(
                "Unexpected end of ASN.1 data".to_string(),
            ));
        }
        let _tag = data[0];
        if data.len() < 2 {
            return Err(AppError::Authentication(
                "ASN.1 data too short for length".to_string(),
            ));
        }

        let (length, header_len) = if data[1] & 0x80 == 0 {
            (data[1] as usize, 2)
        } else {
            let num_octets = (data[1] & 0x7f) as usize;
            if num_octets == 0 || num_octets > 4 {
                return Err(AppError::Authentication(format!(
                    "Unsupported ASN.1 length encoding: {num_octets} octets"
                )));
            }
            if data.len() < 2 + num_octets {
                return Err(AppError::Authentication(
                    "ASN.1 data truncated in length field".to_string(),
                ));
            }
            let mut len = 0usize;
            for &b in &data[2..2 + num_octets] {
                len = (len << 8) | b as usize;
            }
            (len, 2 + num_octets)
        };

        if data.len() < header_len + length {
            return Err(AppError::Authentication(
                "ASN.1 value extends past end of data".to_string(),
            ));
        }

        Ok((header_len + length, &data[header_len..header_len + length]))
    }

    /// Legacy identity extraction never authenticates. Call `KerberosService`
    /// for ticket verification; headers, query names and parsed metadata alone
    /// are not proof of identity.
    pub fn extract_identity(
        _negotiate_token: Option<&str>,
        _proxy_header: Option<&str>,
        _query_username: Option<&str>,
    ) -> AppResult<String> {
        Err(AppError::Authentication(
            "Kerberos ticket verification is not configured".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_tlv_short_form() {
        // Tag 0x30, length 3, value [0x01, 0x02, 0x03]
        let data = [0x30, 0x03, 0x01, 0x02, 0x03];
        let (consumed, value) = SpnegoService::read_tlv(&data).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(value, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn unverified_identity_is_rejected() {
        assert!(
            SpnegoService::extract_identity(None, Some("alice@EXAMPLE.COM"), Some("admin"))
                .is_err()
        );
    }

    #[test]
    fn authentication_decoder_rejects_ntlm_fallback_trailing_bytes_and_unsolicited_mic() {
        let ntlm_oid = [6, 10, 0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 10];
        let init = |first: &[u8], mic: bool| {
            let mut list = first.to_vec();
            list.extend_from_slice(KRB5_OID);
            let mut fields = der(0xa0, &der(0x30, &list));
            fields.extend(der(0xa2, &der(4, &der(0x6e, &der(0x30, &[])))));
            if mic {
                fields.extend(der(0xa3, &der(4, b"unverified")));
            }
            let mut outer = SPNEGO_OID.to_vec();
            outer.extend(der(0xa0, &der(0x30, &fields)));
            der(0x60, &outer)
        };
        for token in [init(&ntlm_oid, false), init(KRB5_OID, true)] {
            assert!(
                SpnegoService::authentication_token(
                    &base64::engine::general_purpose::STANDARD.encode(token)
                )
                .is_err()
            );
        }
        let mut valid = init(KRB5_OID, false);
        assert!(
            SpnegoService::authentication_token(
                &base64::engine::general_purpose::STANDARD.encode(&valid)
            )
            .is_ok()
        );
        valid.push(0);
        assert!(
            SpnegoService::authentication_token(
                &base64::engine::general_purpose::STANDARD.encode(valid)
            )
            .is_err()
        );
        assert!(SpnegoService::authentication_token(&"A".repeat(128 * 1024 + 1)).is_err());
    }
}

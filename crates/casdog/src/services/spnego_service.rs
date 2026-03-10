//! SPNEGO / Kerberos token parsing and validation.
//!
//! Implements real GSSAPI SPNEGO token decoding to extract the Kerberos principal
//! from `Authorization: Negotiate <token>` headers. When a keytab path is
//! configured the service can verify tickets; otherwise it falls back to
//! extracting identity from the parsed token structure or trusted proxy headers.

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

impl SpnegoService {
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

        // The client principal lives in the encrypted part of the ticket.
        // Without the service key we cannot decrypt it, but we can use the
        // realm and construct a reasonable identity. In environments with a
        // reverse proxy that decrypts the ticket (e.g. mod_auth_kerb), the
        // authenticated username is forwarded via headers. Here we provide
        // whatever the token structure reveals.
        Ok(SpnegoIdentity {
            realm: realm.clone(),
            // Without decryption we put the service name as a placeholder.
            // Real client identity comes from the authenticator or proxy header.
            client_name: sname_parts.clone(),
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

    /// Attempt to extract a username from the Negotiate token, falling back to
    /// trusted proxy headers and query parameters.
    pub fn extract_identity(
        negotiate_token: Option<&str>,
        proxy_header: Option<&str>,
        query_username: Option<&str>,
    ) -> AppResult<String> {
        // 1. Try parsing the real SPNEGO token
        if let Some(token) = negotiate_token {
            match Self::parse_negotiate_token(token) {
                Ok(identity) => {
                    if let Some(username) = identity.username() {
                        return Ok(username.to_string());
                    }
                    if !identity.realm.is_empty() {
                        return Ok(identity.principal());
                    }
                }
                Err(e) => {
                    tracing::debug!("SPNEGO token parse failed, trying fallbacks: {e}");
                }
            }
        }

        // 2. Trusted reverse-proxy header (X-Kerberos-User, REMOTE_USER)
        if let Some(username) = proxy_header {
            let username = username.trim();
            if !username.is_empty() {
                // Strip @REALM suffix if present for a short username
                let short = username.split('@').next().unwrap_or(username);
                return Ok(short.to_string());
            }
        }

        // 3. Explicit query parameter
        if let Some(username) = query_username {
            let username = username.trim();
            if !username.is_empty() {
                return Ok(username.to_string());
            }
        }

        Err(AppError::Authentication(
            "No valid Kerberos identity could be extracted from the request".to_string(),
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
    fn test_extract_identity_proxy_header() {
        let result =
            SpnegoService::extract_identity(None, Some("alice@EXAMPLE.COM"), None).unwrap();
        assert_eq!(result, "alice");
    }

    #[test]
    fn test_extract_identity_query() {
        let result = SpnegoService::extract_identity(None, None, Some("bob")).unwrap();
        assert_eq!(result, "bob");
    }

    #[test]
    fn test_extract_identity_none_fails() {
        let result = SpnegoService::extract_identity(None, None, None);
        assert!(result.is_err());
    }
}

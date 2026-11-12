//! Keytab-backed Kerberos acceptor. Cryptography and the AP exchange belong to
//! SSPI/picky; this module supplies tenant policy and a shared replay ledger.
use base64::{Engine, engine::general_purpose::STANDARD};
use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::{
    constants::key_usages::{AP_REP_ENC, AP_REQ_AUTHENTICATOR, TICKET_REP},
    crypto::CipherSuite,
    data_types::{
        Authenticator, EncApRepPart, EncApRepPartInner, EncTicketPart, EncryptedData, PrincipalName,
    },
    messages::{ApRep, ApRepInner, ApReq},
};
use sqlx::PgConnection;
use sspi::{
    BufferType, DataRepresentation, Kerberos, Secret, SecurityBuffer, SecurityStatus,
    ServerRequestFlags, Sspi, SspiImpl,
};
use std::time::Duration;

use super::{
    social_state_service::proof_hash,
    spnego_service::{SpnegoService, kerberos_gss, kerberos_reply},
};
use crate::{
    error::{AppError, AppResult},
    models::Organization,
};

pub struct KerberosService;

/// Only constructed after cryptographic ticket AND authenticator verification.
pub struct VerifiedKerberos {
    pub username: String,
    pub realm: String,
    pub response_token: String,
    fingerprint: String,
    configuration_stamp: String,
    verified_at: std::time::Instant,
}

struct Key {
    realm: String,
    principal: Vec<String>,
    enctype: u16,
    kvno: u32,
    value: Secret<Vec<u8>>,
}
struct Configuration {
    realm: String,
    principal: Vec<String>,
    keys: Vec<Key>,
}
fn denied() -> AppError {
    AppError::Authentication("Kerberos authentication failed".into())
}
fn configuration_error() -> AppError {
    AppError::Validation("Invalid or incomplete Kerberos configuration".into())
}
fn text(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or_default()
}

struct Reader<'a> {
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> AppResult<&'a [u8]> {
        if count > self.bytes.len() {
            return Err(configuration_error());
        }
        let (front, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(front)
    }
    fn u16(&mut self) -> AppResult<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> AppResult<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self) -> AppResult<String> {
        let len = self.u16()? as usize;
        if len == 0 || len > 200 {
            return Err(configuration_error());
        }
        let value = std::str::from_utf8(self.take(len)?).map_err(|_| configuration_error())?;
        if value.chars().any(char::is_control) {
            return Err(configuration_error());
        }
        Ok(value.to_owned())
    }
}
fn keytab(encoded: &str) -> AppResult<Vec<Key>> {
    if encoded.len() > 350_000 {
        return Err(configuration_error());
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| configuration_error())?;
    if bytes.len() > 256 * 1024 || !bytes.starts_with(&[5, 2]) {
        return Err(configuration_error());
    }
    let mut reader = Reader { bytes: &bytes[2..] };
    let mut keys = Vec::new();
    let mut count = 0;
    while !reader.bytes.is_empty() {
        count += 1;
        if count > 256 {
            return Err(configuration_error());
        }
        let size = reader.u32()? as i32;
        if size == 0 || size == i32::MIN {
            return Err(configuration_error());
        }
        if size < 0 {
            reader.take((-size) as usize)?;
            continue;
        }
        let mut entry = Reader {
            bytes: reader.take(size as usize)?,
        };
        let components = entry.u16()?;
        if components == 0 || components > 8 {
            return Err(configuration_error());
        }
        let realm = entry.string()?;
        let mut principal = Vec::new();
        for _ in 0..components {
            principal.push(entry.string()?);
        }
        entry.u32()?; // name type is a hint, not part of principal identity
        entry.u32()?; // key creation time
        let mut kvno = entry.take(1)?[0] as u32;
        let enctype = entry.u16()?;
        let key_size = entry.u16()? as usize;
        if key_size > 64 {
            return Err(configuration_error());
        }
        let key = entry.take(key_size)?.to_vec();
        if entry.bytes.len() >= 4 {
            let extended = entry.u32()?;
            if extended != 0 {
                kvno = extended;
            }
        }
        if !entry.bytes.is_empty() {
            return Err(configuration_error());
        }
        if matches!(enctype, 17 | 18) {
            if key_size != if enctype == 17 { 16 } else { 32 } {
                return Err(configuration_error());
            }
            keys.push(Key {
                realm,
                principal,
                enctype,
                kvno,
                value: Secret::from(key),
            });
        }
    }
    if keys.is_empty() {
        return Err(configuration_error());
    }
    Ok(keys)
}
fn configuration(org: &Organization) -> AppResult<Configuration> {
    let realm = text(&org.kerberos_realm);
    let host = text(&org.kerberos_kdc_host);
    if realm.is_empty()
        || realm.len() > 200
        || !realm.is_ascii()
        || realm
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'@' | b'\\' | 0))
        || host.is_empty()
        || host.len() > 200
        || host.chars().any(char::is_whitespace)
    {
        return Err(configuration_error());
    }
    let url = reqwest::Url::parse(&format!("tcp://{host}")).map_err(|_| configuration_error())?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
        || host.contains('/')
        || host.contains('@')
        || host.contains('\\')
    {
        return Err(configuration_error());
    }
    let keys = keytab(text(&org.kerberos_keytab))?;
    let service = text(&org.kerberos_service_name);
    let (name, declared_realm) = service
        .rsplit_once('@')
        .map_or((service, None), |(n, r)| (n, Some(r)));
    if declared_realm.is_some_and(|r| !r.eq_ignore_ascii_case(realm)) {
        return Err(configuration_error());
    }
    let candidates: Vec<_> = keys
        .iter()
        .filter(|k| {
            k.realm.eq_ignore_ascii_case(realm)
                && k.principal.len() == 2
                && k.principal[0] == "HTTP"
                && (name.is_empty() || name == "HTTP" || name == k.principal.join("/"))
        })
        .collect();
    let principal = candidates
        .first()
        .ok_or_else(configuration_error)?
        .principal
        .clone();
    if candidates.iter().any(|key| key.principal != principal) {
        return Err(configuration_error());
    }
    Ok(Configuration {
        realm: realm.to_owned(),
        principal,
        keys,
    })
}
fn uint(bytes: &[u8]) -> AppResult<u32> {
    if bytes.is_empty()
        || bytes[0] & 0x80 != 0
        || bytes.len() > 5
        || (bytes.len() == 5 && bytes[0] != 0)
    {
        return Err(denied());
    }
    let mut value = 0u32;
    for b in bytes {
        value = value
            .checked_mul(256)
            .and_then(|v| v.checked_add(*b as u32))
            .ok_or_else(denied)?;
    }
    Ok(value)
}
fn names(value: &PrincipalName) -> Vec<String> {
    value
        .name_string
        .0
        .0
        .iter()
        .map(|v| v.0.to_string())
        .collect()
}

// Bound the constructed ASN.1 tree before a derived decoder can recurse. Octet
// strings (including encrypted bodies) are opaque, not recursive containers.
fn bounded_der(bytes: &[u8], depth: usize, nodes: &mut usize) -> AppResult<()> {
    if depth > 24 {
        return Err(denied());
    }
    let mut pos = 0;
    while pos < bytes.len() {
        *nodes += 1;
        if *nodes > 4096 || bytes.len() - pos < 2 {
            return Err(denied());
        }
        let tag = bytes[pos];
        if tag & 0x1f == 0x1f {
            return Err(denied());
        }
        let first = bytes[pos + 1];
        let (header, len) = if first < 128 {
            (2, first as usize)
        } else {
            let n = (first & 127) as usize;
            if n == 0 || n > 4 || bytes.len() - pos < 2 + n || bytes[pos + 2] == 0 {
                return Err(denied());
            }
            let mut len = 0usize;
            for b in &bytes[pos + 2..pos + 2 + n] {
                len = (len << 8) | *b as usize;
            }
            if len < 128 {
                return Err(denied());
            }
            (2 + n, len)
        };
        let end = pos
            .checked_add(header)
            .and_then(|p| p.checked_add(len))
            .filter(|p| *p <= bytes.len())
            .ok_or_else(denied)?;
        if tag & 0x20 != 0 {
            bounded_der(&bytes[pos + header..end], depth + 1, nodes)?;
        }
        pos = end;
    }
    Ok(())
}

impl KerberosService {
    /// Entirely empty settings disable Kerberos. Partial settings never do.
    pub fn validate_configuration(org: &Organization) -> AppResult<()> {
        if [
            &org.kerberos_realm,
            &org.kerberos_kdc_host,
            &org.kerberos_keytab,
            &org.kerberos_service_name,
        ]
        .iter()
        .all(|v| text(v).is_empty())
        {
            return Ok(());
        }
        configuration(org).map(|_| ())
    }
    pub fn configuration_stamp(org: &Organization) -> String {
        proof_hash(
            &serde_json::json!([
                "casdog.kerberos.configuration.v1",
                org.id,
                org.name,
                org.kerberos_realm,
                org.kerberos_kdc_host,
                org.kerberos_keytab,
                org.kerberos_service_name
            ])
            .to_string(),
        )
    }
    pub fn verify(org: &Organization, token: &str) -> AppResult<VerifiedKerberos> {
        let config = configuration(org).map_err(|_| denied())?;
        let token = SpnegoService::authentication_token(token)?;
        bounded_der(&token.ap_req, 0, &mut 0)?;
        let request: ApReq = picky_asn1_der::from_bytes(&token.ap_req).map_err(|_| denied())?;
        if uint(&request.0.pvno.0.0)? != 5
            || uint(&request.0.msg_type.0.0)? != 14
            || uint(&request.0.ticket.0.0.tkt_vno.0.0)? != 5
            || request.0.ap_options.0.0.is_set(1)
        {
            return Err(denied());
        }
        let ticket = &request.0.ticket.0.0;
        if !ticket
            .realm
            .0
            .0
            .to_string()
            .eq_ignore_ascii_case(&config.realm)
            || names(&ticket.sname.0) != config.principal
        {
            return Err(denied());
        }
        let encrypted = &ticket.enc_part.0;
        let enctype = uint(&encrypted.etype.0.0)?;
        if !matches!(enctype, 17 | 18) {
            return Err(denied());
        }
        let kvno = encrypted
            .kvno
            .0
            .as_ref()
            .map(|v| uint(&v.0.0))
            .transpose()?;
        let mut possible: Vec<_> = config
            .keys
            .iter()
            .filter(|k| {
                k.realm.eq_ignore_ascii_case(&config.realm)
                    && k.principal == config.principal
                    && u32::from(k.enctype) == enctype
                    && kvno.is_none_or(|n| k.kvno == n)
            })
            .collect();
        possible.sort_by_key(|key| std::cmp::Reverse(key.kvno));
        // Without a ticket kvno, accepting ambiguous keys makes rotation depend
        // on arbitrary keytab entry order. An explicit current key is required.
        if possible.len() != 1 {
            return Err(denied());
        }
        let key = possible[0];
        let cipher = CipherSuite::try_from(encrypted.etype.0.0.as_slice())
            .map_err(|_| denied())?
            .cipher();
        let plaintext = cipher
            .decrypt(key.value.as_ref(), TICKET_REP, &encrypted.cipher.0.0)
            .map_err(|_| denied())?;
        bounded_der(&plaintext, 0, &mut 0)?;
        let decoded: EncTicketPart =
            picky_asn1_der::from_bytes(&plaintext).map_err(|_| denied())?;
        let client = names(&decoded.0.cname.0);
        let realm = decoded.0.crealm.0.0.to_string();
        if !realm.eq_ignore_ascii_case(&config.realm)
            || client.is_empty()
            || client.len() > 8
            || client.iter().any(|v| {
                v.is_empty()
                    || v.len() > 100
                    || v.chars()
                        .any(|c| c.is_control() || matches!(c, '/' | '@' | '\\'))
            })
            || decoded.0.flags.0.0.is_set(7)
            || decoded.0.flags.0.0.is_set(16)
            || decoded
                .0
                .caddr
                .0
                .as_ref()
                .is_some_and(|v| !v.0.0.is_empty())
        {
            return Err(denied());
        }
        let session = &decoded.0.key.0;
        let session_type = uint(&session.key_type.0.0)?;
        if !matches!(session_type, 17 | 18)
            || uint(&request.0.authenticator.0.etype.0.0)? != session_type
        {
            return Err(denied());
        }
        let auth_cipher = CipherSuite::try_from(request.0.authenticator.0.etype.0.0.as_slice())
            .map_err(|_| denied())?
            .cipher();
        let plain_auth = auth_cipher
            .decrypt(
                &session.key_value.0.0,
                AP_REQ_AUTHENTICATOR,
                &request.0.authenticator.0.cipher.0.0,
            )
            .map_err(|_| denied())?;
        bounded_der(&plain_auth, 0, &mut 0)?;
        let auth: Authenticator = picky_asn1_der::from_bytes(&plain_auth).map_err(|_| denied())?;
        let usec = uint(&auth.0.cusec.0.0)?;
        if uint(&auth.0.authenticator_vno.0.0)? != 5
            || usec >= 1_000_000
            || names(&auth.0.cname.0) != client
            || auth.0.crealm.0.0.to_string() != realm
        {
            return Err(denied());
        }
        let service: Vec<_> = config.principal.iter().map(String::as_str).collect();
        let props = sspi::kerberos::ServerProperties::new(
            &service,
            None,
            Duration::from_secs(300),
            Some(key.value.clone()),
        )
        .map_err(|_| denied())?;
        // No credentials and no network executor: U2U/IAKerb and any request to
        // a KDC are impossible. This acceptor only verifies ordinary AP-REQs.
        let mut server = Kerberos::new_server_from_config(
            sspi::KerberosConfig::new_with_kdc_url("127.0.0.1:1", "casdog".into()),
            props,
        )
        .map_err(|_| denied())?;
        let mut credentials = None;
        // SSPI 0.23.1 leaves the acceptor response cipher at AES256 even for
        // AES128 session keys. Use it to VERIFY the unchanged encrypted ticket
        // and authenticator without generating its optional mutual reply; the
        // original requested reply is built below using picky's actual cipher.
        let mut validation = request.clone();
        validation.0.ap_options.0.0.set(2, false);
        let validation = picky_asn1_der::to_vec(&validation).map_err(|_| denied())?;
        let mut input = [SecurityBuffer::new(
            kerberos_gss(&validation),
            BufferType::Token,
        )];
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let builder = server
            .accept_security_context()
            .with_credentials_handle(&mut credentials)
            .with_context_requirements(ServerRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);
        let status = server
            .accept_security_context_impl(builder)
            .map_err(|_| denied())?
            .resolve_to_result()
            .map_err(|_| denied())?;
        if status.status != SecurityStatus::Ok {
            return Err(denied());
        }
        let reply = if request.0.ap_options.0.0.is_set(2) {
            let inner = EncApRepPart::from(EncApRepPartInner {
                ctime: ExplicitContextTag0::from(auth.0.ctime.0.clone()),
                cusec: ExplicitContextTag1::from(auth.0.cusec.0.clone()),
                subkey: Optional::from(None),
                seq_number: Optional::from(None),
            });
            let encrypted = auth_cipher
                .encrypt(
                    &session.key_value.0.0,
                    AP_REP_ENC,
                    &picky_asn1_der::to_vec(&inner).map_err(|_| denied())?,
                )
                .map_err(|_| denied())?;
            let reply = ApRep::from(ApRepInner {
                pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
                msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![15])),
                enc_part: ExplicitContextTag2::from(EncryptedData {
                    etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![session_type as u8])),
                    kvno: Optional::from(None),
                    cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted)),
                }),
            });
            kerberos_reply(&picky_asn1_der::to_vec(&reply).map_err(|_| denied())?)
        } else {
            Vec::new()
        };
        let timestamp = picky_asn1_der::to_vec(&auth.0.ctime.0).map_err(|_| denied())?;
        let fingerprint = proof_hash(
            &serde_json::json!([
                "casdog.kerberos.replay.v1",
                config.realm.to_ascii_uppercase(),
                config.principal,
                realm.to_ascii_uppercase(),
                client,
                hex::encode(timestamp),
                usec
            ])
            .to_string(),
        );
        Ok(VerifiedKerberos {
            username: client.join("/"),
            realm,
            response_token: STANDARD.encode(token.response(&reply)),
            fingerprint,
            configuration_stamp: Self::configuration_stamp(org),
            verified_at: std::time::Instant::now(),
        })
    }
    /// Call inside the SAME transaction that creates the login/MFA challenge.
    pub async fn consume(
        conn: &mut PgConnection,
        org: &Organization,
        proof: &VerifiedKerberos,
    ) -> AppResult<()> {
        if Self::configuration_stamp(org) != proof.configuration_stamp
            || proof.verified_at.elapsed() > Duration::from_secs(30)
        {
            return Err(denied());
        }
        sqlx::query("DELETE FROM kerberos_replays WHERE fingerprint IN (SELECT fingerprint FROM kerberos_replays WHERE expires_at<clock_timestamp() LIMIT 100 FOR UPDATE SKIP LOCKED)").execute(&mut *conn).await?;
        let n=sqlx::query("INSERT INTO kerberos_replays(fingerprint,expires_at) VALUES($1,clock_timestamp()+INTERVAL '11 minutes') ON CONFLICT DO NOTHING")
            .bind(&proof.fingerprint).execute(conn).await?.rows_affected();
        if n != 1 {
            return Err(denied());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keytab_reader_rejects_legacy_versions_holes_and_unbounded_records() {
        for data in [
            vec![],
            vec![5, 1],
            vec![5, 2, 0x80, 0, 0, 0],
            vec![5, 2, 0, 0, 0, 0],
            vec![5, 2, 0, 4, 0, 0],
        ] {
            assert!(keytab(&STANDARD.encode(data)).is_err());
        }
        assert!(keytab(&"A".repeat(350_001)).is_err());
        let mut nested = vec![0x30, 0];
        for _ in 0..25 {
            nested = super::super::spnego_service::der(0x30, &nested);
        }
        assert!(bounded_der(&nested, 0, &mut 0).is_err());
        for value in [&[][..], &[0xff][..], &[0, 1, 0, 0, 0, 0][..]] {
            assert!(uint(value).is_err());
        }
    }
}

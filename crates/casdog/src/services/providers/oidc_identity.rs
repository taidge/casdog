//! OIDC public-key identity validation. Unverified JWT payloads never become profiles.
use crate::error::{AppError, AppResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use subtle::ConstantTimeEq;

fn invalid() -> AppError {
    AppError::Authentication("OIDC identity verification failed".into())
}

// Reject duplicate object members instead of assigning conflicting JOSE meanings
// to the same signed bytes. serde_json retains its own recursion limit.
pub fn strict_json(bytes: &[u8]) -> AppResult<Value> {
    struct Strict(Value);
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Strict;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("bounded unambiguous JSON")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                    Ok(Strict(Value::Bool(v)))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
                    serde_json::Number::from_f64(v)
                        .map(|n| Strict(Value::Number(n)))
                        .ok_or_else(|| E::custom("invalid number"))
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                    Ok(Strict(Value::String(v.into())))
                }
                fn visit_string<E: de::Error>(self, v: String) -> Result<Strict, E> {
                    Ok(Strict(Value::String(v)))
                }
                fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_none<E: de::Error>(self) -> Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                    let mut v = Vec::new();
                    while let Some(Strict(x)) = a.next_element()? {
                        v.push(x);
                    }
                    Ok(Strict(Value::Array(v)))
                }
                fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                    let mut v = serde_json::Map::new();
                    while let Some(k) = a.next_key::<String>()? {
                        if v.contains_key(&k) {
                            return Err(de::Error::custom("duplicate member"));
                        }
                        let Strict(x) = a.next_value()?;
                        v.insert(k, x);
                    }
                    Ok(Strict(Value::Object(v)))
                }
            }
            d.deserialize_any(V)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut decoder).map_err(|_| invalid())?;
    decoder.end().map_err(|_| invalid())?;
    Ok(value)
}
pub fn supported_alg(name: &str) -> Option<Algorithm> {
    match name {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "ES256" => Some(Algorithm::ES256),
        _ => None,
    }
}
fn string<'a>(v: &'a Value, key: &str) -> AppResult<&'a str> {
    v[key]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 16384 && !s.chars().any(char::is_control))
        .ok_or_else(invalid)
}
fn component(v: &Value, name: &str, max: usize) -> AppResult<Vec<u8>> {
    let raw = string(v, name)?;
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(invalid());
    }
    Ok(bytes)
}
fn public_key(key: &Value, alg: &str) -> AppResult<DecodingKey> {
    if key["use"].as_str().is_some_and(|v| v != "sig")
        || key.get("use").is_some_and(|v| !v.is_string())
        || key["alg"].as_str().is_some_and(|v| v != alg)
        || key.get("alg").is_some_and(|v| !v.is_string())
    {
        return Err(invalid());
    }
    if let Some(ops) = key.get("key_ops") {
        let a = ops.as_array().ok_or_else(invalid)?;
        if a.len() != 1 || a[0].as_str() != Some("verify") {
            return Err(invalid());
        }
    }
    match (key["kty"].as_str(), alg) {
        (Some("RSA"), "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512") => {
            let n = component(key, "n", 1024)?;
            let e = component(key, "e", 8)?;
            if n[0] == 0 || e[0] == 0 {
                return Err(invalid());
            }
            let n = rsa::BigUint::from_bytes_be(&n);
            let e = rsa::BigUint::from_bytes_be(&e);
            if !(2048..=8192).contains(&n.bits()) || e < rsa::BigUint::from(3u32) || e.bits() > 32 {
                return Err(invalid());
            }
            rsa::RsaPublicKey::new(n, e).map_err(|_| invalid())?;
            DecodingKey::from_rsa_components(string(key, "n")?, string(key, "e")?)
                .map_err(|_| invalid())
        }
        (Some("EC"), "ES256") => {
            if key["crv"].as_str() != Some("P-256") {
                return Err(invalid());
            }
            let x = component(key, "x", 32)?;
            let y = component(key, "y", 32)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(invalid());
            }
            let mut point = vec![4];
            point.extend(x);
            point.extend(y);
            p256::PublicKey::from_sec1_bytes(&point).map_err(|_| invalid())?;
            DecodingKey::from_ec_components(string(key, "x")?, string(key, "y")?)
                .map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
/// Verify exact issuer, client audience/authorized party, freshness and the
/// server-created nonce before exposing any ID-token claims to profile mapping.
pub fn verify(
    token: &str,
    jwks: &Value,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    started_at: i64,
    allowed: &[String],
    access_token: &str,
) -> AppResult<Value> {
    if token.is_empty()
        || token.len() > 65536
        || nonce.len() < 32
        || nonce.len() > 256
        || client_id.is_empty()
    {
        return Err(invalid());
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|v| v.is_empty()) {
        return Err(invalid());
    }
    let header = strict_json(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| invalid())?)?;
    if !header.is_object()
        || ["jku", "x5u", "jwk", "x5c", "crit", "b64"]
            .iter()
            .any(|k| header.get(*k).is_some())
    {
        return Err(invalid());
    }
    let alg = string(&header, "alg")?;
    let algorithm = supported_alg(alg).ok_or_else(invalid)?;
    if !allowed.iter().any(|v| v == alg) {
        return Err(invalid());
    }
    if header.get("typ").is_some_and(|v| v.as_str() != Some("JWT")) {
        return Err(invalid());
    }
    let kid = header
        .get("kid")
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
                .ok_or_else(invalid)
        })
        .transpose()?;
    let keys = jwks["keys"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 32)
        .ok_or_else(invalid)?;
    let mut selected = Vec::new();
    for key in keys {
        if !key.is_object()
            || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|k| key.get(*k).is_some())
        {
            return Err(invalid());
        }
        if key.get("kid").is_some_and(|v| !v.is_string()) {
            return Err(invalid());
        }
        if kid.is_some_and(|id| key["kid"].as_str() != Some(id)) {
            continue;
        }
        if kid.is_none()
            && (key["alg"].as_str().is_some_and(|v| v != alg)
                || key["use"].as_str().is_some_and(|v| v != "sig"))
        {
            continue;
        }
        if let Ok(key) = public_key(key, alg) {
            selected.push(key)
        } else if kid.is_some() {
            return Err(invalid());
        }
    }
    if selected.len() != 1 {
        return Err(invalid());
    }
    // Duplicate signed claim names are rejected before the library's verified
    // deserialization, but no unverified values are used to select identity.
    strict_json(&URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| invalid())?)?;
    let mut validation = Validation::new(algorithm);
    validation.leeway = 30;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    let claims = jsonwebtoken::decode::<Value>(token, &selected[0], &validation)
        .map_err(|_| invalid())?
        .claims;
    let now = chrono::Utc::now().timestamp();
    let iat = claims["iat"].as_i64().ok_or_else(invalid)?;
    let exp = claims["exp"].as_i64().ok_or_else(invalid)?;
    if started_at > now + 30
        || started_at < now - 600
        || iat < started_at - 60
        || iat > now + 30
        || exp <= iat
        || exp < now - 30
    {
        return Err(invalid());
    }
    let sub = string(&claims, "sub")?;
    if sub.len() > 512 || sub.trim().is_empty() || sub == "unknown" {
        return Err(invalid());
    }
    let actual_nonce = string(&claims, "nonce")?;
    if !bool::from(actual_nonce.as_bytes().ct_eq(nonce.as_bytes())) {
        return Err(invalid());
    }
    let audiences = match &claims["aud"] {
        Value::String(v) => vec![v.as_str()],
        Value::Array(v) => v
            .iter()
            .map(|v| v.as_str().filter(|s| !s.is_empty()).ok_or_else(invalid))
            .collect::<AppResult<Vec<_>>>()?,
        _ => return Err(invalid()),
    };
    if audiences.is_empty()
        || !audiences.contains(&client_id)
        || audiences
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != audiences.len()
    {
        return Err(invalid());
    }
    if (audiences.len() > 1 || claims.get("azp").is_some())
        && claims["azp"].as_str() != Some(client_id)
    {
        return Err(invalid());
    }
    if claims.get("at_hash").is_some() {
        use sha2::Digest;
        if access_token.is_empty() {
            return Err(invalid());
        }
        let digest = match algorithm {
            Algorithm::RS384 | Algorithm::PS384 => {
                sha2::Sha384::digest(access_token.as_bytes()).to_vec()
            }
            Algorithm::RS512 | Algorithm::PS512 => {
                sha2::Sha512::digest(access_token.as_bytes()).to_vec()
            }
            _ => sha2::Sha256::digest(access_token.as_bytes()).to_vec(),
        };
        let expected = URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2]);
        if !bool::from(
            string(&claims, "at_hash")?
                .as_bytes()
                .ct_eq(expected.as_bytes()),
        ) {
            return Err(invalid());
        }
    }
    Ok(claims)
}

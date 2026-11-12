use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::Md5;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::error::{AppError, AppResult};

pub struct PasswordService;

pub struct ImportedPassword {
    pub hash: String,
    pub password_type: String,
    pub salt: Option<String>,
}

// Bound work derived from imported hash strings before invoking a password KDF.
const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;

impl PasswordService {
    /// Keycloak stores Argon2 parameters separately from raw Base64 digest/salt.
    /// Reconstruct a canonical PHC string; parsing never runs the KDF.
    pub fn import_keycloak_argon(
        secret: &serde_json::Value,
        metadata: &serde_json::Value,
    ) -> AppResult<ImportedPassword> {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        let invalid = || {
            AppError::Validation(
                "Invalid or unsupported Keycloak Argon2 credential parameters".into(),
            )
        };
        if metadata["algorithm"].as_str() != Some("argon2") {
            return Err(invalid());
        }
        if let (Some(a), Some(b)) = (
            metadata.get("additionalParameters"),
            metadata.get("algorithmData"),
        ) {
            if a != b {
                return Err(invalid());
            }
        }
        let parameters = metadata
            .get("additionalParameters")
            .or_else(|| metadata.get("algorithmData"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(invalid)?;
        if parameters.len() != 5
            || parameters.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "type" | "version" | "hashLength" | "memory" | "parallelism"
                )
            })
        {
            return Err(invalid());
        }
        let single = |name: &str| -> AppResult<&str> {
            let a = parameters
                .get(name)
                .and_then(serde_json::Value::as_array)
                .filter(|a| a.len() == 1)
                .ok_or_else(invalid)?;
            a[0].as_str().ok_or_else(invalid)
        };
        let variant = single("type")?;
        if !matches!(variant, "id" | "i" | "d") {
            return Err(invalid());
        }
        let version = match single("version")? {
            "1.3" => 19,
            "1.0" => 16,
            _ => return Err(invalid()),
        };
        let integer = |name: &str| -> AppResult<u32> {
            let v = single(name)?;
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            v.parse().map_err(|_| invalid())
        };
        let memory = integer("memory")?;
        let parallelism = integer("parallelism")?;
        let length = integer("hashLength")?;
        let iterations = metadata["hashIterations"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(invalid)?;
        let decode = |field: &str| -> AppResult<Vec<u8>> {
            let raw = secret[field]
                .as_str()
                .filter(|s| s.len() <= 256)
                .ok_or_else(invalid)?;
            STANDARD
                .decode(raw)
                .or_else(|_| STANDARD_NO_PAD.decode(raw))
                .map_err(|_| invalid())
        };
        let salt = decode("salt")?;
        let digest = decode("value")?;
        if !(8..=64).contains(&salt.len())
            || digest.len() != length as usize
            || !(16..=64).contains(&length)
        {
            return Err(invalid());
        }
        let hash = format!(
            "$argon2{variant}$v={version}$m={memory},t={iterations},p={parallelism}${}${}",
            STANDARD_NO_PAD.encode(salt),
            STANDARD_NO_PAD.encode(digest)
        );
        let kind = if variant == "id" {
            "argon2id"
        } else {
            "argon2"
        };
        Self::validate_encoded_hash(&hash, kind, None).map_err(|_| invalid())?;
        Ok(ImportedPassword {
            hash,
            password_type: kind.into(),
            salt: None,
        })
    }
    /// Canonicalize Casdoor `password` + `passwordType` and native explicit
    /// `password_hash` without ever treating a declared hash as plaintext.
    pub fn normalize_import_fields(
        object: &mut serde_json::Map<String, serde_json::Value>,
        allow_masked_update: bool,
    ) -> AppResult<()> {
        use serde_json::{Value, json};
        let read = |key: &str| -> AppResult<Option<String>> {
            object
                .get(key)
                .filter(|v| !v.is_null())
                .map(|v| {
                    v.as_str().map(str::to_owned).ok_or_else(|| {
                        AppError::Validation(format!("Credential field {key} must be a string"))
                    })
                })
                .transpose()
        };
        let hash = read("password_hash")?;
        let password = read("password")?;
        let kind = read("password_type")?;
        let salt = read("password_salt")?;
        if hash.is_some() && password.is_some() {
            return Err(AppError::Validation(
                "Provide either password or password_hash, not both".into(),
            ));
        }
        let value = hash.as_deref().or(password.as_deref());
        if value == Some("***") {
            if !allow_masked_update {
                return Err(AppError::Validation(
                    "Masked exports do not contain a recoverable password credential".into(),
                ));
            }
            for key in [
                "password",
                "password_hash",
                "password_type",
                "password_salt",
            ] {
                object.remove(key);
            }
            return Ok(());
        }
        let Some(value) = value else {
            if kind.as_deref().is_some_and(|s| !s.is_empty())
                || salt.as_deref().is_some_and(|s| !s.is_empty())
            {
                return Err(AppError::Validation(
                    "Password type/salt cannot change without a password credential".into(),
                ));
            }
            object.remove("password_type");
            object.remove("password_salt");
            return Ok(());
        };
        if value.is_empty() {
            if kind
                .as_deref()
                .is_some_and(|s| !s.is_empty() && s != "plain")
                || salt.as_deref().is_some_and(|s| !s.is_empty())
            {
                return Err(AppError::Validation(
                    "An empty encoded credential cannot be imported".into(),
                ));
            }
            object.remove("password");
            object.insert("password_hash".into(), json!(""));
            object.insert("password_type".into(), json!("argon2"));
            object.insert("password_salt".into(), Value::Null);
            return Ok(());
        }
        let encoded = hash.is_some()
            || kind
                .as_deref()
                .is_some_and(|s| !s.is_empty() && s != "plain");
        let credential = Self::import_credential(value, kind.as_deref(), salt.as_deref(), encoded)?;
        object.remove("password");
        object.insert("password_hash".into(), json!(credential.hash));
        object.insert("password_type".into(), json!(credential.password_type));
        object.insert("password_salt".into(), json!(credential.salt));
        Ok(())
    }
    /// Import callers must distinguish plaintext from a stored credential.
    /// Self-describing encodings can identify their own algorithm; raw digests
    /// require an explicit type instead of guessing from their length.
    pub fn import_credential(
        password: &str,
        password_type: Option<&str>,
        salt: Option<&str>,
        is_hashed: bool,
    ) -> AppResult<ImportedPassword> {
        if password.is_empty() || password == "***" || password.len() > 4096 {
            return Err(AppError::Validation("An actual password credential is required; masked exports cannot restore credentials".into()));
        }
        if !is_hashed {
            if Self::encoded_type(password).is_some() {
                return Err(AppError::Validation("Encoded password supplied as plaintext; declare its passwordType/hash semantics".into()));
            }
            return Ok(ImportedPassword {
                hash: Self::hash_password(password, "argon2", None)?,
                password_type: "argon2".into(),
                salt: None,
            });
        }
        let kind = password_type
            .filter(|t| !t.is_empty())
            .map(str::to_ascii_lowercase)
            .or_else(|| Self::encoded_type(password).map(str::to_owned))
            .ok_or_else(|| {
                AppError::Validation(
                    "A non-self-describing password hash requires passwordType".into(),
                )
            })?;
        if kind == "plain" {
            return Self::import_credential(password, None, None, false);
        }
        Self::validate_encoded_hash(password, &kind, salt)?;
        Ok(ImportedPassword {
            hash: password.into(),
            password_type: kind,
            salt: salt.filter(|s| !s.is_empty()).map(str::to_owned),
        })
    }

    pub fn encoded_type(password: &str) -> Option<&'static str> {
        if password.starts_with("$argon2id$") {
            Some("argon2id")
        } else if password.starts_with("$argon2i$") || password.starts_with("$argon2d$") {
            Some("argon2")
        } else if ["$2a$", "$2b$", "$2y$"]
            .iter()
            .any(|prefix| password.starts_with(prefix))
        {
            Some("bcrypt")
        } else if password.starts_with("pbkdf2_sha256$") {
            Some("pbkdf2-django")
        } else if password.starts_with("$pbkdf2-sha256$") {
            Some("pbkdf2-sha256")
        } else if password.starts_with("$keycloak-pbkdf2-sha256$") {
            Some("keycloak-pbkdf2-sha256")
        } else if password.starts_with("$keycloak-pbkdf2-sha512$") {
            Some("keycloak-pbkdf2-sha512")
        } else {
            None
        }
    }

    /// Validate imported KDF resource parameters without running the KDF.
    pub fn validate_encoded_hash(hash: &str, kind: &str, salt: Option<&str>) -> AppResult<()> {
        let invalid =
            || AppError::Validation("Invalid or unsupported encoded password credential".into());
        if hash.is_empty()
            || hash == "***"
            || hash.len() > 1024
            || salt.is_some_and(|s| s.len() > 256)
        {
            return Err(invalid());
        }
        let valid = match kind.to_ascii_lowercase().as_str() {
            "keycloak-pbkdf2-sha256" | "keycloak-pbkdf2-sha512" => {
                let parts: Vec<_> = hash.split('$').collect();
                parts.len() == 5
                    && parts[0].is_empty()
                    && parts[1] == kind
                    && parts[2]
                        .parse::<u32>()
                        .is_ok_and(|n| (1..=MAX_PBKDF2_ITERATIONS).contains(&n))
                    && STANDARD
                        .decode(parts[3])
                        .is_ok_and(|s| (1..=128).contains(&s.len()))
                    && STANDARD
                        .decode(parts[4])
                        .is_ok_and(|k| matches!(k.len(), 32 | 64))
            }
            "argon2" | "argon2id" | "" => {
                let parsed = PasswordHash::new(hash).map_err(|_| invalid())?;
                let m = parsed.params.get_decimal("m").unwrap_or(0);
                let t = parsed.params.get_decimal("t").unwrap_or(0);
                let p = parsed.params.get_decimal("p").unwrap_or(0);
                matches!(
                    parsed.algorithm.as_str(),
                    "argon2id" | "argon2i" | "argon2d"
                ) && (!kind.eq_ignore_ascii_case("argon2id")
                    || parsed.algorithm.as_str() == "argon2id")
                    && matches!(parsed.version, Some(16 | 19))
                    && (1..=10).contains(&t)
                    && (1..=16).contains(&p)
                    && m >= 8 * p
                    && m <= 262_144
                    && m.saturating_mul(t) <= 786_432
                    && parsed.hash.is_some_and(|h| (16..=64).contains(&h.len()))
                    && parsed
                        .salt
                        .is_some_and(|s| (8..=128).contains(&s.as_str().len()))
            }
            "bcrypt" => {
                hash.len() == 60
                    && Self::encoded_type(hash) == Some("bcrypt")
                    && hash
                        .split('$')
                        .nth(2)
                        .and_then(|cost| cost.parse::<u32>().ok())
                        .is_some_and(|cost| (4..=16).contains(&cost))
                    && hash.as_bytes()[7..]
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'.' | b'/'))
            }
            "salt" | "sha256-salt" => {
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
            }
            "md5-salt" => hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "sha512-salt" => hash.len() == 128 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "pbkdf2-salt" => {
                STANDARD.decode(hash).is_ok_and(|key| key.len() == 64)
                    && STANDARD
                        .decode(salt.unwrap_or_default())
                        .is_ok_and(|salt| salt.len() <= 128)
            }
            "pbkdf2-django" | "pbkdf2-sha256" => {
                let parts: Vec<_> = hash.split('$').collect();
                let fields = match parts.as_slice() {
                    ["pbkdf2_sha256", rounds, salt, hash]
                        if kind.eq_ignore_ascii_case("pbkdf2-django") =>
                    {
                        Some((*rounds, *salt, *hash, true))
                    }
                    ["", "pbkdf2-sha256", rounds, salt, hash]
                        if kind.eq_ignore_ascii_case("pbkdf2-sha256") =>
                    {
                        Some((*rounds, *salt, *hash, false))
                    }
                    _ => None,
                };
                fields.is_some_and(|(rounds, salt, key, django)| {
                    salt.len() <= 256
                        && rounds
                            .parse::<u32>()
                            .is_ok_and(|r| (1..=MAX_PBKDF2_ITERATIONS).contains(&r))
                        && if django {
                            STANDARD.decode(key).is_ok_and(|key| key.len() == 32)
                        } else {
                            key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())
                        }
                })
            }
            "plain" => true,
            _ => false,
        };
        if valid { Ok(()) } else { Err(invalid()) }
    }

    pub fn needs_rehash(hash: &str, kind: &str, salt: Option<&str>) -> bool {
        if !matches!(kind, "argon2" | "argon2id" | "") || salt.is_some_and(|s| !s.is_empty()) {
            return true;
        }
        PasswordHash::new(hash).map_or(true, |p| {
            p.algorithm.as_str() != "argon2id"
                || p.params.get_decimal("m").unwrap_or(0) < 19_456
                || p.params.get_decimal("t").unwrap_or(0) < 2
        })
    }
    /// Supports all Casdoor credential types and the original Casdog aliases.
    pub fn hash_password(
        password: &str,
        password_type: &str,
        salt: Option<&str>,
    ) -> AppResult<String> {
        let salt = salt.unwrap_or_default();
        match password_type.to_lowercase().as_str() {
            "argon2" | "argon2id" | "" => Argon2::default()
                .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                .map(|hash| hash.to_string())
                .map_err(|e| AppError::Internal(format!("Failed to hash password: {e}"))),
            "bcrypt" => {
                // Go's bcrypt rejects overlong input when creating credentials.
                if password.len() > 72 {
                    return Err(AppError::Validation(
                        "Bcrypt passwords cannot exceed 72 bytes".to_string(),
                    ));
                }
                bcrypt::hash(password, 10)
                    .map_err(|e| AppError::Validation(format!("Failed to hash password: {e}")))
            }
            "salt" => Ok(Self::salted_digest::<Sha256>(password, salt)),
            "sha512-salt" => Ok(Self::salted_digest::<Sha512>(password, salt)),
            "md5-salt" => Ok(Self::salted_digest::<Md5>(password, salt)),
            // Original Casdog format, distinct from Casdoor's `salt` algorithm.
            "sha256-salt" => Ok(hex::encode(Sha256::digest(format!("{password}{salt}")))),
            "pbkdf2-salt" => {
                let decoded = STANDARD
                    .decode(salt)
                    .map_err(|_| AppError::Validation("Invalid base64 PBKDF2 salt".to_string()))?;
                Ok(STANDARD.encode(Self::derive_key::<64>(password, &decoded, 27_500)))
            }
            "pbkdf2-django" | "pbkdf2-sha256" => {
                if salt.contains('$') {
                    return Err(AppError::Validation("Salt cannot contain '$'".to_string()));
                }
                if password_type.eq_ignore_ascii_case("pbkdf2-django") {
                    let key = Self::derive_key::<32>(password, salt.as_bytes(), 260_000);
                    Ok(format!(
                        "pbkdf2_sha256$260000${salt}${}",
                        STANDARD.encode(key)
                    ))
                } else {
                    let key = Self::derive_key::<32>(password, salt.as_bytes(), 100_000);
                    Ok(format!("$pbkdf2-sha256$100000${salt}${}", hex::encode(key)))
                }
            }
            "plain" => Ok(password.to_string()),
            _ => Err(AppError::Validation(format!(
                "Unsupported password type: {password_type}"
            ))),
        }
    }

    pub fn verify_password(
        password: &str,
        password_hash: &str,
        password_type: &str,
        salt: Option<&str>,
    ) -> AppResult<bool> {
        let salt = salt.unwrap_or_default();
        let kind = password_type.to_lowercase();
        // Old Casdog markers remain readable for migration, but are never
        // accepted as imported bcrypt/MD5 encodings.
        let old_marker = (kind == "bcrypt" && password_hash.starts_with("$bcrypt-fallback$"))
            || (kind == "md5-salt" && password_hash.starts_with("$md5-fallback$"));
        if !old_marker && Self::validate_encoded_hash(password_hash, &kind, Some(salt)).is_err() {
            return Ok(false);
        }
        match kind.as_str() {
            "keycloak-pbkdf2-sha256" | "keycloak-pbkdf2-sha512" => {
                let parts: Vec<_> = password_hash.split('$').collect();
                let rounds = parts[2]
                    .parse::<u32>()
                    .map_err(|_| AppError::Validation("Invalid Keycloak rounds".into()))?;
                let decoded_salt = STANDARD
                    .decode(parts[3])
                    .map_err(|_| AppError::Validation("Invalid Keycloak salt".into()))?;
                let expected = STANDARD
                    .decode(parts[4])
                    .map_err(|_| AppError::Validation("Invalid Keycloak digest".into()))?;
                let mut computed = vec![0u8; expected.len()];
                if kind == "keycloak-pbkdf2-sha256" {
                    pbkdf2::pbkdf2_hmac::<Sha256>(
                        password.as_bytes(),
                        &decoded_salt,
                        rounds,
                        &mut computed,
                    );
                } else {
                    pbkdf2::pbkdf2_hmac::<Sha512>(
                        password.as_bytes(),
                        &decoded_salt,
                        rounds,
                        &mut computed,
                    );
                }
                Ok(bool::from(computed.ct_eq(&expected)))
            }
            "argon2" | "argon2id" | "" => {
                let Ok(parsed) = PasswordHash::new(password_hash) else {
                    return Ok(false);
                };
                let valid = Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok();
                // Casdoor accepts older records hashed with password + salt, too.
                Ok(valid
                    || (kind == "argon2id"
                        && !salt.is_empty()
                        && Argon2::default()
                            .verify_password(format!("{password}{salt}").as_bytes(), &parsed)
                            .is_ok()))
            }
            "bcrypt" => {
                // Read legacy Casdog fallback hashes for migration, never generate them.
                if let Some(old) = password_hash.strip_prefix("$bcrypt-fallback$") {
                    return Ok(Self::equal(&hex::encode(Sha256::digest(password)), old));
                }
                let Some(cost) = password_hash
                    .split('$')
                    .nth(2)
                    .and_then(|s| s.parse::<u32>().ok())
                else {
                    return Ok(false);
                };
                if !(4..=16).contains(&cost) {
                    return Ok(false);
                }
                Ok(bcrypt::verify(password, password_hash).unwrap_or(false))
            }
            "salt" => Ok(Self::verify_digest::<Sha256>(password, password_hash, salt)),
            "sha512-salt" => Ok(Self::verify_digest::<Sha512>(password, password_hash, salt)
                // Read the old Casdog single-hash format as well.
                || Self::equal(&hex::encode(Sha512::digest(format!("{password}{salt}"))), &password_hash.to_ascii_lowercase())),
            "md5-salt" => {
                if let Some(old) = password_hash.strip_prefix("$md5-fallback$") {
                    return Ok(Self::equal(
                        &hex::encode(Sha256::digest(format!("{password}{salt}"))),
                        old,
                    ));
                }
                Ok(Self::verify_digest::<Md5>(password, password_hash, salt))
            }
            "pbkdf2-django" | "pbkdf2-sha256" => {
                let parts: Vec<_> = password_hash.split('$').collect();
                let (rounds, stored_salt, expected, django) = match parts.as_slice() {
                    ["pbkdf2_sha256", rounds, salt, hash] if kind == "pbkdf2-django" => {
                        (*rounds, *salt, *hash, true)
                    }
                    ["", "pbkdf2-sha256", rounds, salt, hash] if kind == "pbkdf2-sha256" => {
                        (*rounds, *salt, *hash, false)
                    }
                    _ => return Ok(false),
                };
                let Ok(rounds) = rounds.parse::<u32>() else {
                    return Ok(false);
                };
                if !(1..=MAX_PBKDF2_ITERATIONS).contains(&rounds) {
                    return Ok(false);
                }
                let key = Self::derive_key::<32>(password, stored_salt.as_bytes(), rounds);
                let computed = if django {
                    STANDARD.encode(key)
                } else {
                    hex::encode(key)
                };
                let expected = if django {
                    expected.to_owned()
                } else {
                    expected.to_ascii_lowercase()
                };
                Ok(Self::equal(&computed, &expected))
            }
            "pbkdf2-salt" | "sha256-salt" | "plain" => {
                let computed = Self::hash_password(password, &kind, Some(salt))?;
                Ok(Self::equal(&computed, password_hash))
            }
            _ => Err(AppError::Validation(format!(
                "Unsupported password type: {password_type}"
            ))),
        }
    }

    pub fn generate_salt() -> String {
        SaltString::generate(&mut OsRng).to_string()
    }

    fn equal(left: &str, right: &str) -> bool {
        bool::from(left.as_bytes().ct_eq(right.as_bytes()))
    }

    // Casdoor hashes the hex digest again when a nonempty salt is present.
    fn salted_digest<D: Digest>(password: &str, salt: &str) -> String {
        let first = hex::encode(D::digest(password.as_bytes()));
        if salt.is_empty() {
            first
        } else {
            hex::encode(D::digest(format!("{first}{salt}")))
        }
    }

    fn verify_digest<D: Digest>(password: &str, expected: &str, salt: &str) -> bool {
        let expected = &expected.to_ascii_lowercase();
        Self::equal(&Self::salted_digest::<D>(password, salt), expected)
            || (salt.is_empty()
                && Self::equal(
                    &Self::salted_digest::<D>(&hex::encode(D::digest(password.as_bytes())), ""),
                    expected,
                ))
    }

    fn derive_key<const N: usize>(password: &str, salt: &[u8], rounds: u32) -> [u8; N] {
        let mut key = [0u8; N];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, rounds, &mut key);
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casdoor_digest_vectors() {
        // Independently calculated with Python hashlib using Casdoor cred/*.go formats.
        for (kind, salt, expected) in [
            (
                "salt",
                "salt",
                "92d690d4eb4a598d5362f7196dba110e3974a9ea58eb9363be73e987d738afc6",
            ),
            ("md5-salt", "salt", "d514dee5e76bbb718084294c835f312c"),
            (
                "sha512-salt",
                "salt",
                "0a610f0bbf7a92accc7e962c53ef3ed7d7d2cabb16139ae169555a6685056b405fa4a3edb041f27e6d8c29bea70eb9bd89bad9fcfcdf05e23b1b8b99ad1256a5",
            ),
            (
                "salt",
                "",
                "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            ),
            ("md5-salt", "", "5f4dcc3b5aa765d61d8327deb882cf99"),
        ] {
            assert_eq!(
                PasswordService::hash_password("password", kind, Some(salt)).unwrap(),
                expected
            );
            assert!(
                PasswordService::verify_password("password", expected, kind, Some(salt)).unwrap()
            );
            assert!(
                !PasswordService::verify_password("wrong", expected, kind, Some(salt)).unwrap()
            );
        }
    }

    #[test]
    fn casdoor_unsalted_legacy_digest_vectors() {
        for (kind, expected) in [
            (
                "salt",
                "113459eb7bb31bddee85ade5230d6ad5d8b2fb52879e00a84ff6ae1067a210d3",
            ),
            ("md5-salt", "696d29e0940a4957748fe3fc9efd22a3"),
            (
                "sha512-salt",
                "afe99137967ee6f5ec8f08df89dd8076db932e13d4ca8d7b32feda3dc919ae3e1657cf30616523d28500727755eddad5a6e18fe255b407a9c5f6dd8de1a43b99",
            ),
        ] {
            assert!(PasswordService::verify_password("password", expected, kind, None).unwrap());
            assert!(!PasswordService::verify_password("wrong", expected, kind, None).unwrap());
        }
    }

    #[test]
    fn casdoor_pbkdf2_vectors() {
        let keycloak = "p6XETX9kSIy9ZwWTiGafUdPW9KUJsfJSWQD9lWRuomav7bGCMfY03kxznJu2emdUprJ3DVemHMlpE5c0+dmsAA==";
        let django = "pbkdf2_sha256$260000$salt$BOAEc9gQ0CEXQRxBUdHBbIFI/Fh0OEwXzUsCN5cI+kQ=";
        assert_eq!(
            PasswordService::hash_password("password", "pbkdf2-salt", Some("c2FsdA==")).unwrap(),
            keycloak
        );
        assert_eq!(
            PasswordService::hash_password("password", "pbkdf2-django", Some("salt")).unwrap(),
            django
        );
        assert!(
            PasswordService::verify_password("password", keycloak, "pbkdf2-salt", Some("c2FsdA=="))
                .unwrap()
        );
        assert!(
            !PasswordService::verify_password("wrong", keycloak, "pbkdf2-salt", Some("c2FsdA=="))
                .unwrap()
        );
        assert!(
            PasswordService::verify_password("password", django, "pbkdf2-django", None).unwrap()
        );
        assert!(!PasswordService::verify_password("wrong", django, "pbkdf2-django", None).unwrap());
    }

    #[test]
    fn malformed_pbkdf2_is_rejected_before_expensive_work() {
        for hash in [
            "",
            "pbkdf2_sha256$0$salt$hash",
            "pbkdf2_sha256$-1$salt$hash",
            "pbkdf2_sha256$4294967295$salt$hash",
            "pbkdf2_sha1$1$salt$hash",
        ] {
            assert!(
                !PasswordService::verify_password("password", hash, "pbkdf2-django", None).unwrap()
            );
        }
        assert!(
            PasswordService::hash_password("password", "pbkdf2-salt", Some("!invalid!")).is_err()
        );
    }

    #[test]
    fn real_bcrypt_and_argon2id_roundtrip() {
        for kind in [
            "bcrypt",
            "argon2id",
            "argon2",
            "pbkdf2-sha256",
            "sha256-salt",
            "plain",
        ] {
            let hash = PasswordService::hash_password("password", kind, Some("salt")).unwrap();
            assert!(!hash.contains("fallback"));
            if kind == "bcrypt" {
                assert!(hash.starts_with("$2"));
            }
            assert!(
                PasswordService::verify_password("password", &hash, kind, Some("salt")).unwrap()
            );
            assert!(!PasswordService::verify_password("wrong", &hash, kind, Some("salt")).unwrap());
        }
    }

    #[test]
    fn imported_bcrypt_vectors_and_invalid_inputs() {
        // Interoperability vectors from the bcrypt crate's Python and Node tests.
        for hash in [
            "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie",
            "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk5bektyVVa5xnIi",
        ] {
            assert!(
                PasswordService::verify_password(
                    "correctbatteryhorsestapler",
                    hash,
                    "bcrypt",
                    None
                )
                .unwrap()
            );
            assert!(!PasswordService::verify_password("wrong", hash, "bcrypt", None).unwrap());
        }
        for hash in ["invalid", "$2a$xx$invalid", "$2b$31$invalid"] {
            assert!(!PasswordService::verify_password("password", hash, "bcrypt", None).unwrap());
        }
        assert!(PasswordService::hash_password(&"x".repeat(73), "bcrypt", None).is_err());
    }

    #[test]
    fn casdoor_argon2id_legacy_salt_is_accepted() {
        let hash = PasswordService::hash_password("passwordsalt", "argon2id", None).unwrap();
        assert!(
            PasswordService::verify_password("password", &hash, "argon2id", Some("salt")).unwrap()
        );
        assert!(
            !PasswordService::verify_password("password", &hash, "argon2id", Some("other"))
                .unwrap()
        );
        assert!(
            !PasswordService::verify_password("password", "invalid", "argon2id", None).unwrap()
        );
    }

    #[test]
    fn previous_casdog_fallbacks_remain_readable() {
        let bcrypt = format!(
            "$bcrypt-fallback${}",
            hex::encode(Sha256::digest("password"))
        );
        let md5 = format!(
            "$md5-fallback${}",
            hex::encode(Sha256::digest("passwordsalt"))
        );
        for (kind, hash) in [("bcrypt", bcrypt), ("md5-salt", md5)] {
            assert!(
                PasswordService::verify_password("password", &hash, kind, Some("salt")).unwrap()
            );
            assert!(!PasswordService::verify_password("wrong", &hash, kind, Some("salt")).unwrap());
        }
    }

    #[test]
    fn unsupported_type_and_random_salts() {
        assert!(PasswordService::hash_password("password", "unsupported", None).is_err());
        assert_ne!(
            PasswordService::generate_salt(),
            PasswordService::generate_salt()
        );
    }
}

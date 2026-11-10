use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::Md5;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::error::{AppError, AppResult};

pub struct PasswordService;

// Bound work derived from imported hash strings before invoking a password KDF.
const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;

impl PasswordService {
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
        match kind.as_str() {
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
                || Self::equal(&hex::encode(Sha512::digest(format!("{password}{salt}"))), password_hash)),
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
                Ok(Self::equal(&computed, expected))
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

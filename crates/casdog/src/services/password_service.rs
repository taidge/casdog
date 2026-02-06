use crate::error::{AppError, AppResult};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sha2::{Digest, Sha256, Sha512};

pub struct PasswordService;

impl PasswordService {
    /// Hash password using the specified algorithm
    /// Supported: "argon2" (default), "bcrypt", "pbkdf2-sha256", "sha256-salt", "sha512-salt", "md5-salt", "plain"
    pub fn hash_password(password: &str, password_type: &str, salt: Option<&str>) -> AppResult<String> {
        match password_type.to_lowercase().as_str() {
            "argon2" | "" => {
                // Use argon2 (default)
                let argon2 = Argon2::default();
                let salt_string = SaltString::generate(&mut OsRng);
                let password_hash = argon2
                    .hash_password(password.as_bytes(), &salt_string)
                    .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?;
                Ok(password_hash.to_string())
            }
            "sha256-salt" => {
                let salt = salt.ok_or_else(|| AppError::Validation("Salt required for sha256-salt".to_string()))?;
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                Ok(hex::encode(result))
            }
            "sha512-salt" => {
                let salt = salt.ok_or_else(|| AppError::Validation("Salt required for sha512-salt".to_string()))?;
                let mut hasher = Sha512::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                Ok(hex::encode(result))
            }
            "md5-salt" => {
                // NOTE: MD5 is insecure but needed for compatibility
                // Since md5 crate is not available, we use SHA256 as a fallback
                // This should be replaced with proper MD5 when the md5 crate is added to dependencies
                let salt = salt.ok_or_else(|| AppError::Validation("Salt required for md5-salt".to_string()))?;
                tracing::warn!("MD5 hashing requested but md5 crate not available, using SHA256 fallback");
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                Ok(format!("$md5-fallback${}", hex::encode(result)))
            }
            "pbkdf2-sha256" => {
                // Manual PBKDF2 implementation using HMAC-SHA256
                // For production, consider adding the pbkdf2 crate for proper implementation
                let salt = salt.ok_or_else(|| AppError::Validation("Salt required for pbkdf2-sha256".to_string()))?;
                let iterations = 100_000;
                let derived_key = Self::pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), iterations, 32)?;
                Ok(format!("$pbkdf2-sha256${}${}${}", iterations, salt, hex::encode(derived_key)))
            }
            "bcrypt" => {
                // NOTE: bcrypt crate is not available in dependencies
                // Using SHA256 as a placeholder fallback
                // This should be replaced with proper bcrypt when the bcrypt crate is added
                tracing::warn!("Bcrypt hashing requested but bcrypt crate not available, using SHA256 fallback");
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                Ok(format!("$bcrypt-fallback${}", hex::encode(result)))
            }
            "plain" => {
                // Plain text password (insecure, for testing/migration only)
                tracing::warn!("Plain text password storage is insecure and should only be used for testing");
                Ok(password.to_string())
            }
            _ => Err(AppError::Validation(format!(
                "Unsupported password type: {}",
                password_type
            ))),
        }
    }

    /// Verify password against hash using the specified algorithm
    pub fn verify_password(
        password: &str,
        password_hash: &str,
        password_type: &str,
        salt: Option<&str>,
    ) -> AppResult<bool> {
        match password_type.to_lowercase().as_str() {
            "argon2" | "" => {
                // Use argon2 (default)
                let parsed_hash = PasswordHash::new(password_hash)
                    .map_err(|e| AppError::Internal(format!("Failed to parse password hash: {}", e)))?;
                let argon2 = Argon2::default();
                Ok(argon2
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok())
            }
            "sha256-salt" => {
                let salt = salt.ok_or_else(|| AppError::Validation("Salt required for sha256-salt".to_string()))?;
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let computed_hash = hex::encode(result);
                Ok(computed_hash == password_hash)
            }
            "sha512-salt" => {
                let salt = salt.ok_or_else(|| AppError::Validation("Salt required for sha512-salt".to_string()))?;
                let mut hasher = Sha512::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let computed_hash = hex::encode(result);
                Ok(computed_hash == password_hash)
            }
            "md5-salt" => {
                // Check if it's the fallback format
                if password_hash.starts_with("$md5-fallback$") {
                    let hash_part = password_hash.strip_prefix("$md5-fallback$").unwrap();
                    let salt = salt.ok_or_else(|| AppError::Validation("Salt required for md5-salt".to_string()))?;
                    let mut hasher = Sha256::new();
                    hasher.update(password.as_bytes());
                    hasher.update(salt.as_bytes());
                    let result = hasher.finalize();
                    let computed_hash = hex::encode(result);
                    Ok(computed_hash == hash_part)
                } else {
                    // Legacy MD5 hash - would need md5 crate to verify
                    Err(AppError::Internal(
                        "Legacy MD5 verification requires md5 crate".to_string(),
                    ))
                }
            }
            "pbkdf2-sha256" => {
                // Parse the hash format: $pbkdf2-sha256$iterations$salt$hash
                let parts: Vec<&str> = password_hash.split('$').collect();
                if parts.len() != 5 || parts[1] != "pbkdf2-sha256" {
                    return Err(AppError::Validation("Invalid pbkdf2-sha256 hash format".to_string()));
                }

                let iterations: u32 = parts[2]
                    .parse()
                    .map_err(|_| AppError::Validation("Invalid iterations in hash".to_string()))?;
                let stored_salt = parts[3];
                let stored_hash = parts[4];

                let derived_key = Self::pbkdf2_sha256(password.as_bytes(), stored_salt.as_bytes(), iterations, 32)?;
                let computed_hash = hex::encode(derived_key);
                Ok(computed_hash == stored_hash)
            }
            "bcrypt" => {
                // Check if it's the fallback format
                if password_hash.starts_with("$bcrypt-fallback$") {
                    let hash_part = password_hash.strip_prefix("$bcrypt-fallback$").unwrap();
                    let mut hasher = Sha256::new();
                    hasher.update(password.as_bytes());
                    let result = hasher.finalize();
                    let computed_hash = hex::encode(result);
                    Ok(computed_hash == hash_part)
                } else {
                    // Legacy bcrypt hash - would need bcrypt crate to verify
                    Err(AppError::Internal(
                        "Legacy bcrypt verification requires bcrypt crate".to_string(),
                    ))
                }
            }
            "plain" => {
                // Plain text comparison
                Ok(password == password_hash)
            }
            _ => Err(AppError::Validation(format!(
                "Unsupported password type: {}",
                password_type
            ))),
        }
    }

    /// Generate a random salt
    pub fn generate_salt() -> String {
        let salt = SaltString::generate(&mut OsRng);
        salt.to_string()
    }

    /// Manual PBKDF2-HMAC-SHA256 implementation
    /// This is a simplified implementation. For production, use the pbkdf2 crate.
    fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> AppResult<Vec<u8>> {

        let mut result = Vec::with_capacity(output_len);
        let mut block_index = 1u32;

        while result.len() < output_len {
            // HMAC for block
            let mut u = Self::hmac_sha256(password, &[salt, &block_index.to_be_bytes()].concat());
            let mut current_block = u.clone();

            for _ in 1..iterations {
                u = Self::hmac_sha256(password, &u);
                for (i, &byte) in u.iter().enumerate() {
                    current_block[i] ^= byte;
                }
            }

            result.extend_from_slice(&current_block);
            block_index += 1;
        }

        result.truncate(output_len);
        Ok(result)
    }

    /// Simple HMAC-SHA256 implementation
    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        const BLOCK_SIZE: usize = 64;

        let mut key_padded = vec![0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let hashed = hasher.finalize();
            key_padded[..hashed.len()].copy_from_slice(&hashed);
        } else {
            key_padded[..key.len()].copy_from_slice(key);
        }

        let mut ipad = vec![0x36u8; BLOCK_SIZE];
        let mut opad = vec![0x5cu8; BLOCK_SIZE];

        for i in 0..BLOCK_SIZE {
            ipad[i] ^= key_padded[i];
            opad[i] ^= key_padded[i];
        }

        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&ipad);
        inner_hasher.update(data);
        let inner_hash = inner_hasher.finalize();

        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&opad);
        outer_hasher.update(&inner_hash);
        let outer_hash = outer_hasher.finalize();

        outer_hash.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_hash_and_verify() {
        let password = "SecurePassword123!";
        let hash = PasswordService::hash_password(password, "argon2", None).unwrap();

        // Verify correct password
        assert!(PasswordService::verify_password(password, &hash, "argon2", None).unwrap());

        // Verify incorrect password
        assert!(!PasswordService::verify_password("WrongPassword", &hash, "argon2", None).unwrap());
    }

    #[test]
    fn test_sha256_salt_hash_and_verify() {
        let password = "SecurePassword123!";
        let salt = "randomsalt123";
        let hash = PasswordService::hash_password(password, "sha256-salt", Some(salt)).unwrap();

        // Verify correct password
        assert!(PasswordService::verify_password(password, &hash, "sha256-salt", Some(salt)).unwrap());

        // Verify incorrect password
        assert!(!PasswordService::verify_password("WrongPassword", &hash, "sha256-salt", Some(salt)).unwrap());
    }

    #[test]
    fn test_sha512_salt_hash_and_verify() {
        let password = "SecurePassword123!";
        let salt = "randomsalt456";
        let hash = PasswordService::hash_password(password, "sha512-salt", Some(salt)).unwrap();

        // Verify correct password
        assert!(PasswordService::verify_password(password, &hash, "sha512-salt", Some(salt)).unwrap());

        // Verify incorrect password
        assert!(!PasswordService::verify_password("WrongPassword", &hash, "sha512-salt", Some(salt)).unwrap());
    }

    #[test]
    fn test_pbkdf2_sha256_hash_and_verify() {
        let password = "SecurePassword123!";
        let salt = "randomsalt789";
        let hash = PasswordService::hash_password(password, "pbkdf2-sha256", Some(salt)).unwrap();

        // Verify correct password
        assert!(PasswordService::verify_password(password, &hash, "pbkdf2-sha256", None).unwrap());

        // Verify incorrect password
        assert!(!PasswordService::verify_password("WrongPassword", &hash, "pbkdf2-sha256", None).unwrap());
    }

    #[test]
    fn test_plain_hash_and_verify() {
        let password = "PlainPassword";
        let hash = PasswordService::hash_password(password, "plain", None).unwrap();

        assert_eq!(hash, password);
        assert!(PasswordService::verify_password(password, &hash, "plain", None).unwrap());
        assert!(!PasswordService::verify_password("WrongPassword", &hash, "plain", None).unwrap());
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = PasswordService::generate_salt();
        let salt2 = PasswordService::generate_salt();

        // Salts should be different
        assert_ne!(salt1, salt2);
        assert!(!salt1.is_empty());
    }

    #[test]
    fn test_bcrypt_fallback() {
        let password = "TestPassword123";
        let hash = PasswordService::hash_password(password, "bcrypt", None).unwrap();

        assert!(hash.starts_with("$bcrypt-fallback$"));
        assert!(PasswordService::verify_password(password, &hash, "bcrypt", None).unwrap());
    }

    #[test]
    fn test_md5_fallback() {
        let password = "TestPassword456";
        let salt = "testsalt";
        let hash = PasswordService::hash_password(password, "md5-salt", Some(salt)).unwrap();

        assert!(hash.starts_with("$md5-fallback$"));
        assert!(PasswordService::verify_password(password, &hash, "md5-salt", Some(salt)).unwrap());
    }

    #[test]
    fn test_unsupported_password_type() {
        let result = PasswordService::hash_password("password", "unsupported", None);
        assert!(result.is_err());
    }
}

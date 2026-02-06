use crate::error::{AppError, AppResult};
use regex::Regex;
use sqlx::PgPool;
use std::net::IpAddr;

pub struct CheckService;

impl CheckService {
    /// Username validation: 2-39 chars, alphanumeric + underscore + hyphen + dot, must start with letter
    pub fn check_username(username: &str) -> AppResult<()> {
        let len = username.len();
        if len < 2 || len > 39 {
            return Err(AppError::Validation(
                "Username must be between 2 and 39 characters".to_string(),
            ));
        }

        // Must start with a letter
        if !username.chars().next().unwrap().is_alphabetic() {
            return Err(AppError::Validation(
                "Username must start with a letter".to_string(),
            ));
        }

        // Alphanumeric + underscore + hyphen + dot
        let re = Regex::new(r"^[a-zA-Z][a-zA-Z0-9_\-\.]*$").unwrap();
        if !re.is_match(username) {
            return Err(AppError::Validation(
                "Username can only contain letters, numbers, underscores, hyphens, and dots".to_string(),
            ));
        }

        Ok(())
    }

    /// Password complexity based on org password_options JSON array
    /// Options: "AtLeast6", "AtLeast8", "Aa", "NoRepeat", "AtLeastOne!@#", "AtLeastOneDigit"
    pub fn check_password_complexity(
        password: &str,
        options: Option<&serde_json::Value>,
    ) -> AppResult<()> {
        if password.is_empty() {
            return Err(AppError::Validation("Password cannot be empty".to_string()));
        }

        let options_array = match options {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => return Ok(()), // No options, pass validation
        };

        for option in options_array {
            if let Some(opt_str) = option.as_str() {
                match opt_str {
                    "AtLeast6" => {
                        if password.len() < 6 {
                            return Err(AppError::Validation(
                                "Password must be at least 6 characters".to_string(),
                            ));
                        }
                    }
                    "AtLeast8" => {
                        if password.len() < 8 {
                            return Err(AppError::Validation(
                                "Password must be at least 8 characters".to_string(),
                            ));
                        }
                    }
                    "Aa" => {
                        let has_upper = password.chars().any(|c| c.is_uppercase());
                        let has_lower = password.chars().any(|c| c.is_lowercase());
                        if !has_upper || !has_lower {
                            return Err(AppError::Validation(
                                "Password must contain both uppercase and lowercase letters".to_string(),
                            ));
                        }
                    }
                    "NoRepeat" => {
                        // Check for consecutive repeated characters
                        let chars: Vec<char> = password.chars().collect();
                        for i in 0..chars.len().saturating_sub(2) {
                            if chars[i] == chars[i + 1] && chars[i + 1] == chars[i + 2] {
                                return Err(AppError::Validation(
                                    "Password cannot contain 3 or more consecutive repeated characters".to_string(),
                                ));
                            }
                        }
                    }
                    "AtLeastOne!@#" => {
                        let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
                        if !password.chars().any(|c| special_chars.contains(c)) {
                            return Err(AppError::Validation(
                                "Password must contain at least one special character".to_string(),
                            ));
                        }
                    }
                    "AtLeastOneDigit" => {
                        if !password.chars().any(|c| c.is_ascii_digit()) {
                            return Err(AppError::Validation(
                                "Password must contain at least one digit".to_string(),
                            ));
                        }
                    }
                    _ => {} // Unknown option, ignore
                }
            }
        }

        Ok(())
    }

    /// Email format validation
    pub fn check_email(email: &str) -> AppResult<()> {
        if email.is_empty() {
            return Err(AppError::Validation("Email cannot be empty".to_string()));
        }

        // Basic email validation regex
        let re = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        if !re.is_match(email) {
            return Err(AppError::Validation("Invalid email format".to_string()));
        }

        Ok(())
    }

    /// Phone format validation (basic: digits, +, -, spaces, 7-15 chars)
    pub fn check_phone(phone: &str) -> AppResult<()> {
        if phone.is_empty() {
            return Err(AppError::Validation("Phone cannot be empty".to_string()));
        }

        // Remove spaces, hyphens, and plus for counting
        let digits_only: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        let len = digits_only.len();

        if len < 7 || len > 15 {
            return Err(AppError::Validation(
                "Phone number must contain between 7 and 15 digits".to_string(),
            ));
        }

        // Allow only digits, +, -, and spaces
        let re = Regex::new(r"^[0-9+\-\s]+$").unwrap();
        if !re.is_match(phone) {
            return Err(AppError::Validation(
                "Phone number can only contain digits, +, -, and spaces".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if user is locked out (signin_wrong_times >= max, and last_signin_wrong_time within frozen period)
    /// Default: 5 attempts, 15 min freeze
    pub fn check_signin_lockout(
        signin_wrong_times: i32,
        last_signin_wrong_time: Option<&str>,
        max_attempts: Option<i32>,
        frozen_minutes: Option<i32>,
    ) -> AppResult<()> {
        let max_attempts = max_attempts.unwrap_or(5);
        let frozen_minutes = frozen_minutes.unwrap_or(15);

        if signin_wrong_times < max_attempts {
            return Ok(());
        }

        // Check if still within frozen period
        if let Some(last_wrong_time_str) = last_signin_wrong_time {
            if let Ok(last_wrong_time) = chrono::DateTime::parse_from_rfc3339(last_wrong_time_str) {
                let last_wrong_time_utc = last_wrong_time.with_timezone(&chrono::Utc);
                let now = chrono::Utc::now();
                let frozen_duration = chrono::Duration::minutes(frozen_minutes as i64);
                let unlock_time = last_wrong_time_utc + frozen_duration;

                if now < unlock_time {
                    let minutes_left = (unlock_time - now).num_minutes();
                    return Err(AppError::Authentication(format!(
                        "Account is locked due to too many failed login attempts. Try again in {} minutes",
                        minutes_left
                    )));
                }
            }
        }

        Ok(())
    }

    /// Display name validation: 1-100 chars, no control characters
    pub fn check_display_name(name: &str) -> AppResult<()> {
        let len = name.len();
        if len < 1 || len > 100 {
            return Err(AppError::Validation(
                "Display name must be between 1 and 100 characters".to_string(),
            ));
        }

        // No control characters
        if name.chars().any(|c| c.is_control()) {
            return Err(AppError::Validation(
                "Display name cannot contain control characters".to_string(),
            ));
        }

        Ok(())
    }

    /// Signup validation: combines username, password, email, phone checks
    pub fn check_signup(
        username: &str,
        password: &str,
        email: Option<&str>,
        phone: Option<&str>,
        display_name: &str,
        password_options: Option<&serde_json::Value>,
    ) -> AppResult<()> {
        // Check username
        Self::check_username(username)?;

        // Check password
        Self::check_password_complexity(password, password_options)?;

        // Check email if provided
        if let Some(email_str) = email {
            if !email_str.is_empty() {
                Self::check_email(email_str)?;
            }
        }

        // Check phone if provided
        if let Some(phone_str) = phone {
            if !phone_str.is_empty() {
                Self::check_phone(phone_str)?;
            }
        }

        // Check display name
        Self::check_display_name(display_name)?;

        Ok(())
    }

    /// Check if username is actually an email (not allowed as username)
    pub fn check_username_not_email(username: &str) -> AppResult<()> {
        if username.contains('@') {
            return Err(AppError::Validation(
                "Username cannot be an email address".to_string(),
            ));
        }
        Ok(())
    }

    /// Check for duplicate username in database
    pub async fn check_username_duplicate(
        pool: &PgPool,
        owner: &str,
        username: &str,
    ) -> AppResult<()> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE owner = $1 AND name = $2 AND is_deleted = false)",
        )
        .bind(owner)
        .bind(username)
        .fetch_one(pool)
        .await?;

        if exists {
            return Err(AppError::Conflict(format!(
                "Username '{}' already exists",
                username
            )));
        }
        Ok(())
    }

    /// Check for duplicate email in database
    pub async fn check_email_duplicate(
        pool: &PgPool,
        owner: &str,
        email: &str,
    ) -> AppResult<()> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE owner = $1 AND email = $2 AND is_deleted = false)",
        )
        .bind(owner)
        .bind(email)
        .fetch_one(pool)
        .await?;

        if exists {
            return Err(AppError::Conflict(format!(
                "Email '{}' is already registered",
                email
            )));
        }
        Ok(())
    }

    /// Check for duplicate phone in database
    pub async fn check_phone_duplicate(
        pool: &PgPool,
        owner: &str,
        phone: &str,
    ) -> AppResult<()> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE owner = $1 AND phone = $2 AND is_deleted = false)",
        )
        .bind(owner)
        .bind(phone)
        .fetch_one(pool)
        .await?;

        if exists {
            return Err(AppError::Conflict(format!(
                "Phone '{}' is already registered",
                phone
            )));
        }
        Ok(())
    }

    /// Check IP whitelist (user-level, org-level, or app-level)
    /// Whitelist is a comma-separated list of IPs or CIDR ranges.
    /// If whitelist is empty or None, allow all.
    pub fn check_ip_whitelist(client_ip: &str, whitelist: Option<&str>) -> AppResult<()> {
        let whitelist = match whitelist {
            Some(wl) if !wl.trim().is_empty() => wl,
            _ => return Ok(()), // No whitelist configured, allow all
        };

        let client_addr: IpAddr = client_ip.parse().map_err(|_| {
            AppError::Validation(format!("Invalid client IP address: {}", client_ip))
        })?;

        for entry in whitelist.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            // Check if it's a CIDR range (e.g., "192.168.1.0/24")
            if entry.contains('/') {
                if let Some((network_str, prefix_str)) = entry.split_once('/') {
                    if let (Ok(network_addr), Ok(prefix_len)) =
                        (network_str.trim().parse::<IpAddr>(), prefix_str.trim().parse::<u32>())
                    {
                        if Self::ip_in_cidr(&client_addr, &network_addr, prefix_len) {
                            return Ok(());
                        }
                    }
                }
            } else {
                // Direct IP match
                if let Ok(allowed_addr) = entry.parse::<IpAddr>() {
                    if client_addr == allowed_addr {
                        return Ok(());
                    }
                }
            }
        }

        Err(AppError::Authorization(format!(
            "IP address '{}' is not in the allowed whitelist",
            client_ip
        )))
    }

    /// Check if an IP address is within a CIDR range
    fn ip_in_cidr(ip: &IpAddr, network: &IpAddr, prefix_len: u32) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip_v4), IpAddr::V4(net_v4)) => {
                if prefix_len > 32 {
                    return false;
                }
                let ip_bits = u32::from(*ip_v4);
                let net_bits = u32::from(*net_v4);
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                (ip_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(ip_v6), IpAddr::V6(net_v6)) => {
                if prefix_len > 128 {
                    return false;
                }
                let ip_bits = u128::from(*ip_v6);
                let net_bits = u128::from(*net_v6);
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }

    /// Check login permission - whether user has permission to access app
    /// If allow-only permissions exist for this app and user is not in allow list, deny.
    /// If deny permissions exist for this app and user is in deny list, deny.
    pub async fn check_login_permission(
        pool: &PgPool,
        user_id: &str,
        app_id: &str,
    ) -> AppResult<()> {
        // Check if there are any "allow" permissions for this app
        let allow_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM permissions WHERE resource_id = $1 AND effect = 'allow' AND is_deleted = false",
        )
        .bind(app_id)
        .fetch_one(pool)
        .await?;

        if allow_count > 0 {
            // There are allow-list permissions; check if user is in the allow list
            let user_allowed: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM permissions p
                    WHERE p.resource_id = $1
                      AND p.effect = 'allow'
                      AND p.is_deleted = false
                      AND (
                          p.users::jsonb @> to_jsonb($2::text)
                          OR EXISTS (
                              SELECT 1 FROM roles r
                              WHERE r.is_deleted = false
                                AND p.roles::jsonb @> to_jsonb(r.name::text)
                                AND r.users::jsonb @> to_jsonb($2::text)
                          )
                      )
                )
                "#,
            )
            .bind(app_id)
            .bind(user_id)
            .fetch_one(pool)
            .await?;

            if !user_allowed {
                return Err(AppError::Authorization(
                    "You do not have permission to access this application".to_string(),
                ));
            }
        }

        // Check if there are any "deny" permissions for this user on this app
        let user_denied: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM permissions p
                WHERE p.resource_id = $1
                  AND p.effect = 'deny'
                  AND p.is_deleted = false
                  AND (
                      p.users::jsonb @> to_jsonb($2::text)
                      OR EXISTS (
                          SELECT 1 FROM roles r
                          WHERE r.is_deleted = false
                            AND p.roles::jsonb @> to_jsonb(r.name::text)
                            AND r.users::jsonb @> to_jsonb($2::text)
                      )
                  )
            )
            "#,
        )
        .bind(app_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        if user_denied {
            return Err(AppError::Authorization(
                "Access to this application has been denied for your account".to_string(),
            ));
        }

        Ok(())
    }

    /// Record signin error and check if account should be locked.
    /// Increments signin_wrong_times and updates last_signin_wrong_time.
    pub async fn record_signin_error(
        pool: &PgPool,
        user_id: &str,
        _max_attempts: i32,
        _frozen_minutes: i32,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE users SET signin_wrong_times = signin_wrong_times + 1, last_signin_wrong_time = $1 WHERE id = $2",
        )
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(user_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Reset signin error count (on successful login)
    pub async fn reset_signin_error(pool: &PgPool, user_id: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE users SET signin_wrong_times = 0, last_signin_wrong_time = NULL WHERE id = $1",
        )
        .bind(user_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Check password expiration based on org settings.
    /// Returns true if password is expired.
    /// If expire_days is 0 or None, password never expires.
    pub fn check_password_expired(
        last_change_time: Option<&str>,
        password_expire_days: Option<i32>,
    ) -> AppResult<bool> {
        let expire_days = match password_expire_days {
            Some(days) if days > 0 => days,
            _ => return Ok(false), // Never expires
        };

        let last_change = match last_change_time {
            Some(time_str) if !time_str.is_empty() => {
                chrono::DateTime::parse_from_rfc3339(time_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| {
                        // If we can't parse, assume epoch (always expired)
                        chrono::Utc::now() - chrono::Duration::days(365 * 100)
                    })
            }
            _ => {
                // No last change time recorded, treat as never changed (expired)
                return Ok(true);
            }
        };

        let now = chrono::Utc::now();
        let expiration = last_change + chrono::Duration::days(expire_days as i64);

        Ok(now > expiration)
    }

    /// Check invitation code validity.
    /// Finds an invitation matching the code for the owner.
    /// Checks if it's for the right application (or "All").
    /// Checks remaining quota.
    /// Returns the invitation ID on success.
    pub async fn check_invitation_code(
        pool: &PgPool,
        owner: &str,
        code: &str,
        application_name: Option<&str>,
    ) -> AppResult<String> {
        let row: Option<(String, Option<String>, i32, i32)> = sqlx::query_as(
            r#"
            SELECT id, application, quota, used_count
            FROM invitations
            WHERE owner = $1 AND code = $2 AND is_deleted = false
            "#,
        )
        .bind(owner)
        .bind(code)
        .fetch_optional(pool)
        .await?;

        let (invitation_id, invitation_app, quota, used_count) = row.ok_or_else(|| {
            AppError::Validation("Invalid invitation code".to_string())
        })?;

        // Check if the invitation is for the right application
        if let Some(app_name) = application_name {
            if let Some(ref inv_app) = invitation_app {
                if inv_app != "All" && inv_app != app_name {
                    return Err(AppError::Validation(
                        "Invitation code is not valid for this application".to_string(),
                    ));
                }
            }
        }

        // Check remaining quota (quota of -1 means unlimited)
        if quota >= 0 && used_count >= quota {
            return Err(AppError::Validation(
                "Invitation code has been fully used".to_string(),
            ));
        }

        Ok(invitation_id)
    }

    /// Full signup validation (enhanced version).
    /// Validates username, password, email, phone, display name, duplicates,
    /// and required signup items from the application's signup_items configuration.
    pub async fn check_user_signup(
        pool: &PgPool,
        owner: &str,
        username: &str,
        password: &str,
        email: Option<&str>,
        phone: Option<&str>,
        display_name: &str,
        password_options: Option<&serde_json::Value>,
        signup_items: Option<&serde_json::Value>,
    ) -> AppResult<()> {
        // Check username format
        Self::check_username(username)?;
        Self::check_username_not_email(username)?;

        // Check duplicates
        Self::check_username_duplicate(pool, owner, username).await?;

        // Check password complexity
        Self::check_password_complexity(password, password_options)?;

        // Check email if required/provided
        if let Some(email) = email {
            if !email.is_empty() {
                Self::check_email(email)?;
                Self::check_email_duplicate(pool, owner, email).await?;
            }
        }

        // Check phone if required/provided
        if let Some(phone) = phone {
            if !phone.is_empty() {
                Self::check_phone(phone)?;
                Self::check_phone_duplicate(pool, owner, phone).await?;
            }
        }

        // Check display name
        Self::check_display_name(display_name)?;

        // Check required signup items from signup_items JSON
        if let Some(serde_json::Value::Array(items)) = signup_items {
            for item in items {
                if let (Some(name), Some(required)) = (
                    item.get("name").and_then(|n| n.as_str()),
                    item.get("required").and_then(|r| r.as_bool()),
                ) {
                    if required {
                        match name {
                            "Email" if email.map_or(true, |e| e.is_empty()) => {
                                return Err(AppError::Validation(
                                    "Email is required".to_string(),
                                ));
                            }
                            "Phone" if phone.map_or(true, |p| p.is_empty()) => {
                                return Err(AppError::Validation(
                                    "Phone is required".to_string(),
                                ));
                            }
                            "Display name" if display_name.is_empty() => {
                                return Err(AppError::Validation(
                                    "Display name is required".to_string(),
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_check_username() {
        // Valid usernames
        assert!(CheckService::check_username("alice").is_ok());
        assert!(CheckService::check_username("user123").is_ok());
        assert!(CheckService::check_username("user_name").is_ok());
        assert!(CheckService::check_username("user-name").is_ok());
        assert!(CheckService::check_username("user.name").is_ok());

        // Invalid usernames
        assert!(CheckService::check_username("a").is_err()); // Too short
        assert!(CheckService::check_username("1user").is_err()); // Must start with letter
        assert!(CheckService::check_username("user@name").is_err()); // Invalid char
        assert!(CheckService::check_username(&"a".repeat(40)).is_err()); // Too long
    }

    #[test]
    fn test_check_password_complexity() {
        let options_at_least_6 = json!(["AtLeast6"]);
        let options_at_least_8 = json!(["AtLeast8"]);
        let options_aa = json!(["Aa"]);
        let options_digit = json!(["AtLeastOneDigit"]);
        let options_special = json!(["AtLeastOne!@#"]);
        let options_no_repeat = json!(["NoRepeat"]);

        // AtLeast6
        assert!(CheckService::check_password_complexity("pass12", Some(&options_at_least_6)).is_ok());
        assert!(CheckService::check_password_complexity("pass", Some(&options_at_least_6)).is_err());

        // AtLeast8
        assert!(CheckService::check_password_complexity("password", Some(&options_at_least_8)).is_ok());
        assert!(CheckService::check_password_complexity("pass12", Some(&options_at_least_8)).is_err());

        // Aa (uppercase and lowercase)
        assert!(CheckService::check_password_complexity("Password", Some(&options_aa)).is_ok());
        assert!(CheckService::check_password_complexity("password", Some(&options_aa)).is_err());
        assert!(CheckService::check_password_complexity("PASSWORD", Some(&options_aa)).is_err());

        // AtLeastOneDigit
        assert!(CheckService::check_password_complexity("pass1", Some(&options_digit)).is_ok());
        assert!(CheckService::check_password_complexity("password", Some(&options_digit)).is_err());

        // AtLeastOne!@#
        assert!(CheckService::check_password_complexity("pass!", Some(&options_special)).is_ok());
        assert!(CheckService::check_password_complexity("password", Some(&options_special)).is_err());

        // NoRepeat
        assert!(CheckService::check_password_complexity("password", Some(&options_no_repeat)).is_ok());
        assert!(CheckService::check_password_complexity("passsword", Some(&options_no_repeat)).is_err());
    }

    #[test]
    fn test_check_email() {
        // Valid emails
        assert!(CheckService::check_email("user@example.com").is_ok());
        assert!(CheckService::check_email("user.name@example.co.uk").is_ok());

        // Invalid emails
        assert!(CheckService::check_email("").is_err());
        assert!(CheckService::check_email("user").is_err());
        assert!(CheckService::check_email("user@").is_err());
        assert!(CheckService::check_email("@example.com").is_err());
    }

    #[test]
    fn test_check_phone() {
        // Valid phones
        assert!(CheckService::check_phone("1234567").is_ok());
        assert!(CheckService::check_phone("+1-234-567-8901").is_ok());
        assert!(CheckService::check_phone("123 456 7890").is_ok());

        // Invalid phones
        assert!(CheckService::check_phone("").is_err());
        assert!(CheckService::check_phone("123456").is_err()); // Too short
        assert!(CheckService::check_phone("1234567890123456").is_err()); // Too long
        assert!(CheckService::check_phone("123abc456").is_err()); // Invalid chars
    }

    #[test]
    fn test_check_display_name() {
        // Valid display names
        assert!(CheckService::check_display_name("John Doe").is_ok());
        assert!(CheckService::check_display_name("Alice").is_ok());

        // Invalid display names
        assert!(CheckService::check_display_name("").is_err()); // Too short
        assert!(CheckService::check_display_name(&"a".repeat(101)).is_err()); // Too long
        assert!(CheckService::check_display_name("John\nDoe").is_err()); // Control char
    }

    #[test]
    fn test_check_signup() {
        let password_options = json!(["AtLeast6", "Aa", "AtLeastOneDigit"]);

        // Valid signup
        assert!(CheckService::check_signup(
            "alice",
            "Password1",
            Some("alice@example.com"),
            Some("+1234567890"),
            "Alice Smith",
            Some(&password_options)
        )
        .is_ok());

        // Invalid username
        assert!(CheckService::check_signup(
            "a",
            "Password1",
            Some("alice@example.com"),
            Some("+1234567890"),
            "Alice Smith",
            Some(&password_options)
        )
        .is_err());

        // Invalid password
        assert!(CheckService::check_signup(
            "alice",
            "pass",
            Some("alice@example.com"),
            Some("+1234567890"),
            "Alice Smith",
            Some(&password_options)
        )
        .is_err());
    }

    #[test]
    fn test_check_username_not_email() {
        // Valid usernames (not emails)
        assert!(CheckService::check_username_not_email("alice").is_ok());
        assert!(CheckService::check_username_not_email("user.name").is_ok());
        assert!(CheckService::check_username_not_email("user-123").is_ok());

        // Invalid: email addresses
        assert!(CheckService::check_username_not_email("user@example.com").is_err());
        assert!(CheckService::check_username_not_email("name@domain").is_err());
    }

    #[test]
    fn test_check_ip_whitelist() {
        // No whitelist - allow all
        assert!(CheckService::check_ip_whitelist("192.168.1.1", None).is_ok());
        assert!(CheckService::check_ip_whitelist("192.168.1.1", Some("")).is_ok());
        assert!(CheckService::check_ip_whitelist("192.168.1.1", Some("  ")).is_ok());

        // Exact IP match
        assert!(CheckService::check_ip_whitelist(
            "192.168.1.1",
            Some("192.168.1.1, 10.0.0.1")
        )
        .is_ok());
        assert!(CheckService::check_ip_whitelist(
            "10.0.0.1",
            Some("192.168.1.1, 10.0.0.1")
        )
        .is_ok());
        assert!(CheckService::check_ip_whitelist(
            "172.16.0.1",
            Some("192.168.1.1, 10.0.0.1")
        )
        .is_err());

        // CIDR match
        assert!(CheckService::check_ip_whitelist(
            "192.168.1.50",
            Some("192.168.1.0/24")
        )
        .is_ok());
        assert!(CheckService::check_ip_whitelist(
            "192.168.2.1",
            Some("192.168.1.0/24")
        )
        .is_err());

        // Mixed IP and CIDR
        assert!(CheckService::check_ip_whitelist(
            "10.0.0.5",
            Some("192.168.1.1, 10.0.0.0/24")
        )
        .is_ok());
    }

    #[test]
    fn test_check_password_expired() {
        // No expire days - never expires
        assert!(!CheckService::check_password_expired(Some("2020-01-01T00:00:00Z"), None).unwrap());
        assert!(!CheckService::check_password_expired(Some("2020-01-01T00:00:00Z"), Some(0)).unwrap());

        // No last change time - expired
        assert!(CheckService::check_password_expired(None, Some(90)).unwrap());
        assert!(CheckService::check_password_expired(Some(""), Some(90)).unwrap());

        // Old password - expired (set to year 2020, 90-day expiry)
        assert!(CheckService::check_password_expired(
            Some("2020-01-01T00:00:00+00:00"),
            Some(90)
        )
        .unwrap());

        // Very recent password - not expired
        let recent = chrono::Utc::now().to_rfc3339();
        assert!(!CheckService::check_password_expired(Some(&recent), Some(90)).unwrap());
    }
}

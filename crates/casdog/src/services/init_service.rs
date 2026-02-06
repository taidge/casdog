use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::services::cert_service::CertService;
use crate::services::user_service::UserService;

pub struct InitService;

impl InitService {
    /// Initialize the database with built-in seed data if not already present.
    ///
    /// This mirrors Casdoor's `object/init.go` InitDb() function, creating the
    /// built-in organization, admin user, application, certificate, permission,
    /// Casbin model, adapter, and enforcer records needed for first startup.
    pub async fn init_db(pool: &PgPool) -> AppResult<()> {
        // Phase 1: Check if built-in org already has full seed data.
        // The migration 001 inserts a minimal org row, but we need to check
        // whether the rich seed data (account_items, etc.) has been applied.
        // We use the presence of init_score > 0 as the indicator that the full
        // init has run, since migration 001 only sets defaults (init_score = 0).
        let fully_initialized: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM organizations WHERE name = 'built-in' AND init_score > 0)",
        )
        .fetch_one(pool)
        .await?;

        if fully_initialized {
            tracing::info!("Database already initialized with seed data, skipping");
            return Ok(());
        }

        tracing::info!("Initializing database with built-in seed data...");

        // Order matters: org first, then entities that reference it
        Self::upsert_built_in_org(pool).await?;
        Self::upsert_built_in_user(pool).await?;
        Self::upsert_built_in_cert(pool).await?;
        Self::upsert_built_in_app(pool).await?;
        Self::upsert_built_in_permission(pool).await?;
        Self::create_built_in_api_model(pool).await?;
        Self::create_built_in_user_model(pool).await?;
        Self::create_built_in_api_adapter(pool).await?;
        Self::create_built_in_user_adapter(pool).await?;
        Self::create_built_in_api_enforcer(pool).await?;
        Self::create_built_in_user_enforcer(pool).await?;
        Self::upsert_built_in_provider(pool).await?;

        tracing::info!("Database initialization complete");
        Ok(())
    }

    // ─── Organization ───────────────────────────────────────────────

    async fn upsert_built_in_org(pool: &PgPool) -> AppResult<()> {
        let account_items = serde_json::json!([
            {"name": "Organization", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "ID", "visible": true, "viewRule": "Public", "modifyRule": "Immutable"},
            {"name": "Name", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "Display name", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Avatar", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "User type", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "Password", "visible": true, "viewRule": "Self", "modifyRule": "Self"},
            {"name": "Email", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Phone", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Country code", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "Country/Region", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Location", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Address", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Affiliation", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Title", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "ID card type", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "ID card", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Real name", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "ID verification", "visible": true, "viewRule": "Self", "modifyRule": "Self"},
            {"name": "Homepage", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Bio", "visible": true, "viewRule": "Public", "modifyRule": "Self"},
            {"name": "Tag", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "Signup application", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "Register type", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "Register source", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "Roles", "visible": true, "viewRule": "Public", "modifyRule": "Immutable"},
            {"name": "Permissions", "visible": true, "viewRule": "Public", "modifyRule": "Immutable"},
            {"name": "Groups", "visible": true, "viewRule": "Public", "modifyRule": "Admin"},
            {"name": "3rd-party logins", "visible": true, "viewRule": "Self", "modifyRule": "Self"},
            {"name": "Properties", "visible": true, "viewRule": "Admin", "modifyRule": "Admin"},
            {"name": "Is admin", "visible": true, "viewRule": "Admin", "modifyRule": "Admin"},
            {"name": "Is forbidden", "visible": true, "viewRule": "Admin", "modifyRule": "Admin"},
            {"name": "Is deleted", "visible": true, "viewRule": "Admin", "modifyRule": "Admin"},
            {"name": "Multi-factor authentication", "visible": true, "viewRule": "Self", "modifyRule": "Self"},
            {"name": "WebAuthn credentials", "visible": true, "viewRule": "Self", "modifyRule": "Self"},
            {"name": "Managed accounts", "visible": true, "viewRule": "Self", "modifyRule": "Self"},
            {"name": "MFA accounts", "visible": true, "viewRule": "Self", "modifyRule": "Self"},
        ]);

        let country_codes = serde_json::json!([
            "US", "ES", "FR", "DE", "GB", "CN", "JP", "KR", "VN", "ID", "SG", "IN"
        ]);
        let password_options = serde_json::json!(["AtLeast6"]);
        let languages = serde_json::json!([
            "en", "es", "fr", "de", "ja", "zh", "vi", "pt", "tr", "pl", "uk"
        ]);

        // Upsert: the row may already exist from migration 001 with minimal data
        sqlx::query(
            r#"INSERT INTO organizations (
                id, owner, name, display_name, website_url,
                password_type, password_options,
                country_codes, languages, tags, user_types,
                init_score, enable_soft_deletion, is_profile_public,
                use_email_as_username, enable_tour,
                account_items,
                created_at, updated_at
            ) VALUES (
                $1, 'admin', 'built-in', 'Built-in Organization', 'https://example.com',
                'argon2', $2,
                $3, $4, '[]'::jsonb, '[]'::jsonb,
                2000, false, false,
                false, true,
                $5,
                NOW(), NOW()
            )
            ON CONFLICT (name) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                website_url = EXCLUDED.website_url,
                password_type = EXCLUDED.password_type,
                password_options = EXCLUDED.password_options,
                country_codes = EXCLUDED.country_codes,
                languages = EXCLUDED.languages,
                tags = EXCLUDED.tags,
                user_types = EXCLUDED.user_types,
                init_score = EXCLUDED.init_score,
                enable_soft_deletion = EXCLUDED.enable_soft_deletion,
                is_profile_public = EXCLUDED.is_profile_public,
                use_email_as_username = EXCLUDED.use_email_as_username,
                enable_tour = EXCLUDED.enable_tour,
                account_items = EXCLUDED.account_items,
                updated_at = NOW()"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&password_options)
        .bind(&country_codes)
        .bind(&languages)
        .bind(&account_items)
        .execute(pool)
        .await?;

        tracing::info!("Created/updated built-in organization");
        Ok(())
    }

    // ─── User ───────────────────────────────────────────────────────

    async fn upsert_built_in_user(pool: &PgPool) -> AppResult<()> {
        let password_hash = UserService::hash_password("123")?;

        sqlx::query(
            r#"INSERT INTO users (
                id, owner, name, display_name, password_hash,
                user_type, avatar, email, phone,
                country_code, affiliation, tag,
                is_admin, is_forbidden, is_deleted,
                signup_application, register_type, register_source,
                score, ranking,
                created_ip, properties,
                created_at, updated_at
            ) VALUES (
                $1, 'built-in', 'admin', 'Admin', $2,
                'normal-user', '', 'admin@example.com', '12345678910',
                'US', 'Example Inc.', 'staff',
                true, false, false,
                'app-built-in', 'Add User', 'built-in/admin',
                2000, 1,
                '127.0.0.1', '{}'::jsonb,
                NOW(), NOW()
            )
            ON CONFLICT (owner, name) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                password_hash = EXCLUDED.password_hash,
                user_type = EXCLUDED.user_type,
                email = EXCLUDED.email,
                phone = EXCLUDED.phone,
                country_code = EXCLUDED.country_code,
                affiliation = EXCLUDED.affiliation,
                tag = EXCLUDED.tag,
                is_admin = EXCLUDED.is_admin,
                signup_application = EXCLUDED.signup_application,
                register_type = EXCLUDED.register_type,
                register_source = EXCLUDED.register_source,
                score = EXCLUDED.score,
                ranking = EXCLUDED.ranking,
                created_ip = EXCLUDED.created_ip,
                properties = EXCLUDED.properties,
                updated_at = NOW()"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&password_hash)
        .execute(pool)
        .await?;

        tracing::info!("Created/updated built-in admin user (admin/123)");
        Ok(())
    }

    // ─── Certificate ────────────────────────────────────────────────

    async fn upsert_built_in_cert(pool: &PgPool) -> AppResult<()> {
        // Check if cert already exists with keys populated
        let existing: Option<(String, String)> = sqlx::query_as(
            "SELECT certificate, private_key FROM certificates WHERE owner = 'admin' AND name = 'cert-built-in'",
        )
        .fetch_optional(pool)
        .await?;

        if let Some((cert, key)) = &existing {
            if !cert.is_empty() && !key.is_empty() {
                tracing::info!("Built-in certificate already exists with keys, skipping");
                return Ok(());
            }
        }

        // Generate a real RSA key pair for JWT signing
        let (public_pem, private_pem) = CertService::generate_key_pair("RS256", 4096)?;

        sqlx::query(
            r#"INSERT INTO certificates (
                id, owner, name, created_at, display_name, scope,
                type, crypto_algorithm, bit_size, expire_in_years,
                certificate, private_key
            ) VALUES (
                $1, 'admin', 'cert-built-in', NOW(), 'Built-in Cert', 'JWT',
                'x509', 'RS256', 4096, 20,
                $2, $3
            )
            ON CONFLICT (owner, name) DO UPDATE SET
                certificate = EXCLUDED.certificate,
                private_key = EXCLUDED.private_key"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&public_pem)
        .bind(&private_pem)
        .execute(pool)
        .await?;

        tracing::info!("Created/updated built-in certificate (RS256 4096-bit)");
        Ok(())
    }

    // ─── Application ────────────────────────────────────────────────

    async fn upsert_built_in_app(pool: &PgPool) -> AppResult<()> {
        // Check if application already exists
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM applications WHERE owner = 'admin' AND name = 'app-built-in')",
        )
        .fetch_one(pool)
        .await?;

        if exists {
            tracing::info!("Built-in application already exists, skipping");
            return Ok(());
        }

        let client_id = Uuid::new_v4().to_string().replace('-', "");
        let client_secret = Uuid::new_v4().to_string().replace('-', "");

        let signup_items = serde_json::json!([
            {"name": "ID", "visible": false, "required": true, "prompted": false, "rule": "Random"},
            {"name": "Username", "visible": true, "required": true, "prompted": false, "rule": "None"},
            {"name": "Display name", "visible": true, "required": true, "prompted": false, "rule": "None"},
            {"name": "Password", "visible": true, "required": true, "prompted": false, "rule": "None"},
            {"name": "Confirm password", "visible": true, "required": true, "prompted": false, "rule": "None"},
            {"name": "Email", "visible": true, "required": true, "prompted": false, "rule": "Normal"},
            {"name": "Phone", "visible": true, "required": true, "prompted": false, "rule": "None"},
            {"name": "Agreement", "visible": true, "required": true, "prompted": false, "rule": "None"},
        ]);

        let signin_methods = serde_json::json!([
            {"name": "Password", "displayName": "Password", "rule": "All"},
            {"name": "Verification code", "displayName": "Verification code", "rule": "All"},
            {"name": "WebAuthn", "displayName": "WebAuthn", "rule": "None"},
            {"name": "Face ID", "displayName": "Face ID", "rule": "None"},
        ]);

        let signin_items = serde_json::json!([
            {"name": "Username", "visible": true, "label": "", "placeholder": "", "rule": "None"},
            {"name": "Password", "visible": true, "label": "", "placeholder": "", "rule": "None"},
        ]);

        let providers = serde_json::json!([
            {"name": "provider_captcha_default", "canSignUp": false, "canSignIn": false, "canUnlink": false, "prompted": false, "signupGroup": "", "rule": "None"},
        ]);

        sqlx::query(
            r#"INSERT INTO applications (
                id, owner, name, display_name,
                logo, homepage_url, organization,
                client_id, client_secret, redirect_uris,
                token_format, expire_in_hours, refresh_expire_in_hours,
                cert, enable_password, enable_signin_session,
                enable_code_signin, enable_internal_signup, enable_idp_signup,
                form_offset,
                signup_items, signin_methods, signin_items,
                grant_types, providers, tags,
                created_at, updated_at
            ) VALUES (
                $1, 'admin', 'app-built-in', 'Casdog',
                '', 'https://casdog.org', 'built-in',
                $2, $3, '',
                'JWT', 168, 336,
                'cert-built-in', true, true,
                true, true, true,
                2,
                $4, $5, $6,
                '["authorization_code","password","client_credentials","token","id_token","refresh_token"]'::jsonb,
                $7, '[]'::jsonb,
                NOW(), NOW()
            )"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&client_id)
        .bind(&client_secret)
        .bind(&signup_items)
        .bind(&signin_methods)
        .bind(&signin_items)
        .bind(&providers)
        .execute(pool)
        .await?;

        tracing::info!("Created built-in application (client_id: {})", client_id);
        Ok(())
    }

    // ─── Permission ─────────────────────────────────────────────────

    async fn upsert_built_in_permission(pool: &PgPool) -> AppResult<()> {
        // Permission model uses TEXT columns for resources/actions (not JSONB)
        sqlx::query(
            r#"INSERT INTO permissions (
                id, owner, name, display_name, description,
                resource_type, resources, actions, effect,
                is_enabled,
                created_at, updated_at
            ) VALUES (
                $1, 'built-in', 'permission-built-in', 'Built-in Permission', 'Built-in Permission',
                'Application', 'app-built-in', 'Read,Write,Admin', 'Allow',
                true,
                NOW(), NOW()
            )
            ON CONFLICT (owner, name) DO NOTHING"#,
        )
        .bind(Uuid::new_v4().to_string())
        .execute(pool)
        .await?;

        tracing::info!("Created built-in permission");
        Ok(())
    }

    // ─── Casbin Models ──────────────────────────────────────────────

    async fn create_built_in_api_model(pool: &PgPool) -> AppResult<()> {
        let model_text = r#"[request_definition]
r = subOwner, subName, method, urlPath, objOwner, objName

[policy_definition]
p = subOwner, subName, method, urlPath, objOwner, objName

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (r.subOwner == p.subOwner || p.subOwner == "*") && \
    (r.subName == p.subName || p.subName == "*" || r.subName != "anonymous" && p.subName == "!anonymous") && \
    (r.method == p.method || p.method == "*") && \
    (keyMatch2(r.urlPath, p.urlPath) || p.urlPath == "*") && \
    (r.objOwner == p.objOwner || p.objOwner == "*") && \
    (r.objName == p.objName || p.objName == "*") || \
    (r.subOwner == r.objOwner && r.subName == r.objName)"#;

        sqlx::query(
            r#"INSERT INTO casbin_models (
                id, owner, name, display_name, description,
                model_text, is_enabled,
                created_at, updated_at
            ) VALUES (
                $1, 'built-in', 'api-model-built-in', 'API Model', 'Built-in API authorization model',
                $2, true,
                NOW(), NOW()
            )
            ON CONFLICT (owner, name) DO NOTHING"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(model_text)
        .execute(pool)
        .await?;

        tracing::info!("Created built-in API Casbin model");
        Ok(())
    }

    async fn create_built_in_user_model(pool: &PgPool) -> AppResult<()> {
        let model_text = r#"[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"#;

        sqlx::query(
            r#"INSERT INTO casbin_models (
                id, owner, name, display_name, description,
                model_text, is_enabled,
                created_at, updated_at
            ) VALUES (
                $1, 'built-in', 'user-model-built-in', 'Built-in Model', 'Built-in user authorization model',
                $2, true,
                NOW(), NOW()
            )
            ON CONFLICT (owner, name) DO NOTHING"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(model_text)
        .execute(pool)
        .await?;

        tracing::info!("Created built-in user Casbin model");
        Ok(())
    }

    // ─── Casbin Adapters ────────────────────────────────────────────

    async fn create_built_in_api_adapter(pool: &PgPool) -> AppResult<()> {
        sqlx::query(
            r#"INSERT INTO casbin_adapters (
                id, owner, name, display_name, description,
                adapter_type, is_enabled,
                created_at, updated_at
            ) VALUES (
                $1, 'built-in', 'api-adapter-built-in', 'API Adapter', 'Built-in API adapter (casbin_api_rule table)',
                'database', true,
                NOW(), NOW()
            )
            ON CONFLICT (owner, name) DO NOTHING"#,
        )
        .bind(Uuid::new_v4().to_string())
        .execute(pool)
        .await?;

        tracing::info!("Created built-in API Casbin adapter");
        Ok(())
    }

    async fn create_built_in_user_adapter(pool: &PgPool) -> AppResult<()> {
        sqlx::query(
            r#"INSERT INTO casbin_adapters (
                id, owner, name, display_name, description,
                adapter_type, is_enabled,
                created_at, updated_at
            ) VALUES (
                $1, 'built-in', 'user-adapter-built-in', 'User Adapter', 'Built-in user adapter (casbin_user_rule table)',
                'database', true,
                NOW(), NOW()
            )
            ON CONFLICT (owner, name) DO NOTHING"#,
        )
        .bind(Uuid::new_v4().to_string())
        .execute(pool)
        .await?;

        tracing::info!("Created built-in user Casbin adapter");
        Ok(())
    }

    // ─── Casbin Enforcers ───────────────────────────────────────────

    async fn create_built_in_api_enforcer(pool: &PgPool) -> AppResult<()> {
        // We need the IDs of the model and adapter to create the enforcer FK references.
        let model_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM casbin_models WHERE owner = 'built-in' AND name = 'api-model-built-in'",
        )
        .fetch_optional(pool)
        .await?;

        let adapter_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM casbin_adapters WHERE owner = 'built-in' AND name = 'api-adapter-built-in'",
        )
        .fetch_optional(pool)
        .await?;

        sqlx::query(
            r#"INSERT INTO casbin_enforcers (
                id, owner, name, display_name, description,
                model_id, adapter_id, is_enabled,
                created_at, updated_at
            ) VALUES (
                $1, 'built-in', 'api-enforcer-built-in', 'API Enforcer', 'Built-in API enforcer',
                $2, $3, true,
                NOW(), NOW()
            )
            ON CONFLICT (owner, name) DO NOTHING"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(model_id)
        .bind(adapter_id)
        .execute(pool)
        .await?;

        tracing::info!("Created built-in API Casbin enforcer");
        Ok(())
    }

    async fn create_built_in_user_enforcer(pool: &PgPool) -> AppResult<()> {
        let model_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM casbin_models WHERE owner = 'built-in' AND name = 'user-model-built-in'",
        )
        .fetch_optional(pool)
        .await?;

        let adapter_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM casbin_adapters WHERE owner = 'built-in' AND name = 'user-adapter-built-in'",
        )
        .fetch_optional(pool)
        .await?;

        sqlx::query(
            r#"INSERT INTO casbin_enforcers (
                id, owner, name, display_name, description,
                model_id, adapter_id, is_enabled,
                created_at, updated_at
            ) VALUES (
                $1, 'built-in', 'user-enforcer-built-in', 'User Enforcer', 'Built-in user enforcer',
                $2, $3, true,
                NOW(), NOW()
            )
            ON CONFLICT (owner, name) DO NOTHING"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(model_id)
        .bind(adapter_id)
        .execute(pool)
        .await?;

        tracing::info!("Created built-in user Casbin enforcer");
        Ok(())
    }

    // ─── Providers ──────────────────────────────────────────────────

    async fn upsert_built_in_provider(pool: &PgPool) -> AppResult<()> {
        // Casdoor creates three built-in providers: captcha, balance, and dummy payment
        let providers = [
            (
                "provider_captcha_default",
                "Captcha Default",
                "Captcha",
                "Default",
            ),
            ("provider_balance", "Balance", "Payment", "Balance"),
            (
                "provider_payment_dummy",
                "Dummy Payment",
                "Payment",
                "Dummy",
            ),
        ];

        for (name, display_name, category, ptype) in providers {
            sqlx::query(
                r#"INSERT INTO providers (
                    id, owner, name, display_name, category, type,
                    created_at, updated_at
                ) VALUES (
                    $1, 'admin', $2, $3, $4, $5,
                    NOW(), NOW()
                )
                ON CONFLICT (owner, name) DO NOTHING"#,
            )
            .bind(Uuid::new_v4().to_string())
            .bind(name)
            .bind(display_name)
            .bind(category)
            .bind(ptype)
            .execute(pool)
            .await?;
        }

        tracing::info!("Created built-in providers");
        Ok(())
    }
}

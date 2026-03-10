// Diesel schema definitions for all Casdog tables.
// Generated from migrations 001 through 014.
//
// Note: All timestamp columns use Timestamptz to match the Rust DateTime<Utc> type.
// The underlying PostgreSQL columns may be TIMESTAMP or TIMESTAMPTZ; PG implicitly
// converts when the session timezone is UTC (which is the typical server setting).

// ---------------------------------------------------------------------------
// Core identity tables
// ---------------------------------------------------------------------------

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    organizations (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        website_url -> Nullable<VarChar>,
        favicon -> Nullable<VarChar>,
        password_type -> VarChar,
        default_avatar -> Nullable<VarChar>,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        // 009 expansion
        logo -> Nullable<VarChar>,
        logo_dark -> Nullable<VarChar>,
        password_salt -> Nullable<VarChar>,
        password_options -> Nullable<Jsonb>,
        password_obfuscator_type -> Nullable<VarChar>,
        password_obfuscator_key -> Nullable<VarChar>,
        password_expire_days -> Integer,
        default_password -> Nullable<VarChar>,
        master_password -> Nullable<VarChar>,
        master_verification_code -> Nullable<VarChar>,
        user_types -> Nullable<Jsonb>,
        tags -> Nullable<Jsonb>,
        country_codes -> Nullable<Jsonb>,
        default_application -> Nullable<VarChar>,
        init_score -> Integer,
        languages -> Nullable<Jsonb>,
        theme_data -> Nullable<Jsonb>,
        account_menu -> Nullable<VarChar>,
        enable_soft_deletion -> Bool,
        is_profile_public -> Bool,
        use_email_as_username -> Bool,
        enable_tour -> Bool,
        disable_signin -> Bool,
        ip_restriction -> Nullable<VarChar>,
        ip_whitelist -> Nullable<VarChar>,
        has_privilege_consent -> Bool,
        account_items -> Nullable<Jsonb>,
        nav_items -> Nullable<Jsonb>,
        user_nav_items -> Nullable<Jsonb>,
        widget_items -> Nullable<Jsonb>,
        mfa_items -> Nullable<Jsonb>,
        mfa_remember_in_hours -> Integer,
        org_balance -> Double,
        user_balance -> Double,
        balance_credit -> Double,
        balance_currency -> Nullable<VarChar>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    users (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        password_hash -> VarChar,
        display_name -> VarChar,
        email -> Nullable<VarChar>,
        phone -> Nullable<VarChar>,
        avatar -> Nullable<VarChar>,
        is_admin -> Bool,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        // 005 MFA
        preferred_mfa_type -> Nullable<VarChar>,
        mfa_enabled -> Bool,
        // 009 expansion - Identity & Authentication
        external_id -> Nullable<VarChar>,
        user_type -> Nullable<VarChar>,
        password_salt -> Nullable<VarChar>,
        password_type -> Nullable<VarChar>,
        hash -> Nullable<VarChar>,
        pre_hash -> Nullable<VarChar>,
        register_type -> Nullable<VarChar>,
        register_source -> Nullable<VarChar>,
        access_key -> Nullable<VarChar>,
        access_secret -> Nullable<VarChar>,
        // 009 expansion - Profile Information
        first_name -> Nullable<VarChar>,
        last_name -> Nullable<VarChar>,
        avatar_type -> Nullable<VarChar>,
        permanent_avatar -> Nullable<VarChar>,
        email_verified -> Bool,
        country_code -> Nullable<VarChar>,
        region -> Nullable<VarChar>,
        location -> Nullable<VarChar>,
        address -> Nullable<Jsonb>,
        affiliation -> Nullable<VarChar>,
        title -> Nullable<VarChar>,
        homepage -> Nullable<VarChar>,
        bio -> Nullable<VarChar>,
        // 009 expansion - Personal Details
        id_card_type -> Nullable<VarChar>,
        id_card -> Nullable<VarChar>,
        real_name -> Nullable<VarChar>,
        is_verified -> Bool,
        tag -> Nullable<VarChar>,
        language -> Nullable<VarChar>,
        gender -> Nullable<VarChar>,
        birthday -> Nullable<VarChar>,
        education -> Nullable<VarChar>,
        is_default_avatar -> Bool,
        is_online -> Bool,
        // 009 expansion - Gamification & Balance
        score -> Integer,
        karma -> Integer,
        ranking -> Integer,
        balance -> Double,
        balance_credit -> Double,
        currency -> Nullable<VarChar>,
        balance_currency -> Nullable<VarChar>,
        // 009 expansion - Status
        is_forbidden -> Bool,
        signup_application -> Nullable<VarChar>,
        // 009 expansion - Social Provider IDs
        provider_ids -> Nullable<Jsonb>,
        // 009 expansion - Sign-in Tracking
        created_ip -> Nullable<VarChar>,
        last_signin_time -> Nullable<VarChar>,
        last_signin_ip -> Nullable<VarChar>,
        last_signin_wrong_time -> Nullable<VarChar>,
        signin_wrong_times -> Integer,
        // 009 expansion - MFA (additional)
        mfa_phone_enabled -> Bool,
        mfa_email_enabled -> Bool,
        totp_secret -> Nullable<VarChar>,
        recovery_codes -> Nullable<Jsonb>,
        // 009 expansion - Security
        last_change_password_time -> Nullable<VarChar>,
        need_update_password -> Bool,
        ip_whitelist -> Nullable<VarChar>,
        // 009 expansion - Properties & Custom
        properties -> Nullable<Jsonb>,
        custom -> Nullable<Jsonb>,
        // 009 expansion - LDAP
        ldap -> Nullable<VarChar>,
        // 009 expansion - Invitation
        invitation -> Nullable<VarChar>,
        invitation_code -> Nullable<VarChar>,
        // 009 expansion - Groups
        groups -> Nullable<Jsonb>,
        // 009 expansion - Managed accounts
        managed_accounts -> Nullable<Jsonb>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    applications (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        logo -> Nullable<VarChar>,
        homepage_url -> Nullable<VarChar>,
        description -> Nullable<Text>,
        organization -> VarChar,
        client_id -> VarChar,
        client_secret -> VarChar,
        redirect_uris -> Text,
        token_format -> VarChar,
        expire_in_hours -> Integer,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        // 003 enhancement
        cert -> Nullable<VarChar>,
        // 009 expansion
        refresh_expire_in_hours -> Integer,
        signup_url -> Nullable<VarChar>,
        signin_url -> Nullable<VarChar>,
        forget_url -> Nullable<VarChar>,
        terms_of_use -> Nullable<VarChar>,
        signup_html -> Nullable<Text>,
        signin_html -> Nullable<Text>,
        signup_items -> Nullable<Jsonb>,
        signin_items -> Nullable<Jsonb>,
        signin_methods -> Nullable<Jsonb>,
        grant_types -> Nullable<Jsonb>,
        providers -> Nullable<Jsonb>,
        saml_reply_url -> Nullable<VarChar>,
        enable_password -> Bool,
        enable_signin_session -> Bool,
        enable_auto_signin -> Bool,
        enable_code_signin -> Bool,
        enable_saml_compress -> Bool,
        enable_saml_c14n10 -> Bool,
        enable_web_authn -> Bool,
        enable_link_with_email -> Bool,
        enable_internal_signup -> Bool,
        enable_idp_signup -> Bool,
        form_offset -> Integer,
        form_side_html -> Nullable<Text>,
        form_background_url -> Nullable<VarChar>,
        form_css -> Nullable<Text>,
        form_css_mobile -> Nullable<Text>,
        tags -> Nullable<Jsonb>,
        invitation_codes -> Nullable<Jsonb>,
        default_code_expire_minutes -> Integer,
        footer_text -> Nullable<VarChar>,
        // 011 logout
        logout_url -> Nullable<VarChar>,
        logout_redirect_uris -> Nullable<Text>,
    }
}

// ---------------------------------------------------------------------------
// RBAC tables
// ---------------------------------------------------------------------------

diesel::table! {
    roles (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        is_enabled -> Bool,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_roles (id) {
        id -> VarChar,
        user_id -> VarChar,
        role_id -> VarChar,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    permissions (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        resource_type -> VarChar,
        resources -> Text,
        actions -> Text,
        effect -> VarChar,
        is_enabled -> Bool,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    role_permissions (id) {
        id -> VarChar,
        role_id -> VarChar,
        permission_id -> VarChar,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    casbin_rule (id) {
        id -> Integer,
        ptype -> VarChar,
        v0 -> VarChar,
        v1 -> VarChar,
        v2 -> VarChar,
        v3 -> Nullable<VarChar>,
        v4 -> Nullable<VarChar>,
        v5 -> Nullable<VarChar>,
    }
}

// ---------------------------------------------------------------------------
// Provider & token tables
// ---------------------------------------------------------------------------

diesel::table! {
    providers (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        display_name -> VarChar,
        category -> VarChar,
        #[sql_name = "type"]
        type_ -> VarChar,
        sub_type -> Nullable<VarChar>,
        method -> Nullable<VarChar>,
        client_id -> Nullable<VarChar>,
        client_secret -> Nullable<VarChar>,
        client_id2 -> Nullable<VarChar>,
        client_secret2 -> Nullable<VarChar>,
        cert -> Nullable<Text>,
        custom_auth_url -> Nullable<VarChar>,
        custom_token_url -> Nullable<VarChar>,
        custom_user_info_url -> Nullable<VarChar>,
        custom_logo -> Nullable<VarChar>,
        scopes -> Nullable<Text>,
        user_mapping -> Nullable<Text>,
        http_headers -> Nullable<Text>,
        host -> Nullable<VarChar>,
        port -> Nullable<Integer>,
        disable_ssl -> Bool,
        title -> Nullable<VarChar>,
        content -> Nullable<Text>,
        receiver -> Nullable<VarChar>,
        region_id -> Nullable<VarChar>,
        sign_name -> Nullable<VarChar>,
        template_code -> Nullable<VarChar>,
        app_id -> Nullable<VarChar>,
        endpoint -> Nullable<VarChar>,
        intranet_endpoint -> Nullable<VarChar>,
        domain -> Nullable<VarChar>,
        bucket -> Nullable<VarChar>,
        path_prefix -> Nullable<VarChar>,
        metadata -> Nullable<Text>,
        idp -> Nullable<VarChar>,
        issuer_url -> Nullable<VarChar>,
        enable_sign_authn_request -> Bool,
        provider_url -> Nullable<VarChar>,
    }
}

diesel::table! {
    tokens (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        application -> VarChar,
        organization -> VarChar,
        user_id -> VarChar,
        code -> Nullable<VarChar>,
        access_token -> VarChar,
        refresh_token -> Nullable<VarChar>,
        access_token_hash -> Nullable<VarChar>,
        refresh_token_hash -> Nullable<VarChar>,
        expires_in -> BigInt,
        scope -> VarChar,
        token_type -> VarChar,
        code_challenge -> Nullable<VarChar>,
        code_is_used -> Bool,
        code_expire_in -> Nullable<BigInt>,
        // 003 enhancement
        nonce -> Nullable<VarChar>,
        redirect_uri -> Nullable<Text>,
        code_challenge_method -> Nullable<VarChar>,
    }
}

// ---------------------------------------------------------------------------
// Group tables
// ---------------------------------------------------------------------------

diesel::table! {
    groups (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        display_name -> VarChar,
        manager -> Nullable<VarChar>,
        contact_email -> Nullable<VarChar>,
        #[sql_name = "type"]
        type_ -> Nullable<VarChar>,
        parent_id -> Nullable<VarChar>,
        is_top_group -> Bool,
        is_enabled -> Bool,
    }
}

diesel::table! {
    user_groups (id) {
        id -> VarChar,
        user_id -> VarChar,
        group_id -> VarChar,
        created_at -> Timestamptz,
    }
}

// ---------------------------------------------------------------------------
// Session & certificate tables
// ---------------------------------------------------------------------------

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    sessions (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        application -> VarChar,
        created_at -> Timestamptz,
        user_id -> VarChar,
        session_id -> VarChar,
        // 010 enhancement
        expires_at -> Nullable<Timestamptz>,
        client_ip -> Nullable<VarChar>,
    }
}

diesel::table! {
    certificates (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        display_name -> VarChar,
        scope -> VarChar,
        #[sql_name = "type"]
        type_ -> VarChar,
        crypto_algorithm -> VarChar,
        bit_size -> Integer,
        expire_in_years -> Integer,
        certificate -> Text,
        private_key -> Text,
    }
}

// ---------------------------------------------------------------------------
// Resource, webhook, syncer tables
// ---------------------------------------------------------------------------

diesel::table! {
    resources (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        user_id -> VarChar,
        provider -> Nullable<VarChar>,
        application -> Nullable<VarChar>,
        tag -> Nullable<VarChar>,
        parent -> Nullable<VarChar>,
        file_name -> VarChar,
        file_type -> VarChar,
        file_format -> Nullable<VarChar>,
        file_size -> BigInt,
        url -> VarChar,
        description -> Nullable<Text>,
    }
}

diesel::table! {
    webhooks (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        organization -> VarChar,
        url -> VarChar,
        method -> VarChar,
        content_type -> VarChar,
        headers -> Nullable<Text>,
        events -> Nullable<Text>,
        is_user_extended -> Bool,
        is_enabled -> Bool,
    }
}

diesel::table! {
    syncers (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        organization -> VarChar,
        #[sql_name = "type"]
        type_ -> VarChar,
        database_type -> Nullable<VarChar>,
        ssl_mode -> Nullable<VarChar>,
        host -> VarChar,
        port -> Integer,
        user_name -> VarChar,
        password -> VarChar,
        database_name -> Nullable<VarChar>,
        table_name -> Nullable<VarChar>,
        table_columns -> Nullable<Text>,
        affiliation_table -> Nullable<VarChar>,
        avatar_base_url -> Nullable<VarChar>,
        error_text -> Nullable<Text>,
        sync_interval -> Integer,
        is_read_only -> Bool,
        is_enabled -> Bool,
    }
}

// ---------------------------------------------------------------------------
// Verification & invitation tables
// ---------------------------------------------------------------------------

diesel::table! {
    verifications (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        remote_addr -> Nullable<VarChar>,
        #[sql_name = "type"]
        type_ -> VarChar,
        user_id -> VarChar,
        provider -> VarChar,
        receiver -> VarChar,
        code -> VarChar,
        is_used -> Bool,
    }
}

diesel::table! {
    invitations (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        display_name -> VarChar,
        code -> VarChar,
        is_regexp -> Bool,
        quota -> Integer,
        used_count -> Integer,
        application -> Nullable<VarChar>,
        username -> Nullable<VarChar>,
        email -> Nullable<VarChar>,
        phone -> Nullable<VarChar>,
        signup_group -> Nullable<VarChar>,
        default_code -> Nullable<VarChar>,
        state -> VarChar,
    }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

diesel::table! {
    records (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        created_at -> Timestamptz,
        organization -> Nullable<VarChar>,
        client_ip -> Nullable<VarChar>,
        user_id -> Nullable<VarChar>,
        method -> VarChar,
        request_uri -> VarChar,
        action -> VarChar,
        object -> Nullable<Text>,
        is_triggered -> Bool,
    }
}

// ---------------------------------------------------------------------------
// Social login & MFA tables (004, 005, 006)
// ---------------------------------------------------------------------------

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    user_provider_links (id) {
        id -> VarChar,
        owner -> VarChar,
        user_id -> VarChar,
        provider_type -> VarChar,
        provider_id -> VarChar,
        provider_username -> Nullable<VarChar>,
        provider_display_name -> Nullable<VarChar>,
        provider_email -> Nullable<VarChar>,
        provider_avatar_url -> Nullable<Text>,
        access_token -> Nullable<Text>,
        refresh_token -> Nullable<Text>,
        expires_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa (id) {
        id -> VarChar,
        user_id -> VarChar,
        mfa_type -> VarChar,
        secret -> Nullable<Text>,
        recovery_codes -> Nullable<Text>,
        is_enabled -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_webauthn_credentials (id) {
        id -> VarChar,
        user_id -> VarChar,
        name -> VarChar,
        credential_data -> Text,
        created_at -> Timestamptz,
    }
}

// ---------------------------------------------------------------------------
// Casbin advanced tables (007)
// ---------------------------------------------------------------------------

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    casbin_models (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        model_text -> Text,
        is_enabled -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    casbin_adapters (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        adapter_type -> VarChar,
        host -> Nullable<VarChar>,
        database_type -> Nullable<VarChar>,
        is_enabled -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    casbin_enforcers (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        model_id -> Nullable<VarChar>,
        adapter_id -> Nullable<VarChar>,
        is_enabled -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

// ---------------------------------------------------------------------------
// E-commerce tables (008, 014)
// ---------------------------------------------------------------------------

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    products (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        image -> Nullable<VarChar>,
        detail -> Nullable<Text>,
        currency -> Nullable<VarChar>,
        price -> Double,
        quantity -> Integer,
        sold -> Integer,
        tag -> Nullable<VarChar>,
        state -> VarChar,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    plans (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        price_per_month -> Double,
        price_per_year -> Double,
        currency -> Nullable<VarChar>,
        role -> Nullable<VarChar>,
        options -> Nullable<Text>,
        is_enabled -> Bool,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    pricings (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        plans -> Nullable<Text>,
        trial_duration -> Nullable<Integer>,
        application -> Nullable<VarChar>,
        is_enabled -> Bool,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    subscriptions (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        user_id -> VarChar,
        plan_id -> VarChar,
        pricing_id -> Nullable<VarChar>,
        start_date -> Timestamptz,
        end_date -> Nullable<Timestamptz>,
        period -> Nullable<VarChar>,
        state -> VarChar,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    payments (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        provider_id -> Nullable<VarChar>,
        payment_type -> VarChar,
        product_id -> Nullable<VarChar>,
        product_name -> Nullable<VarChar>,
        user_id -> Nullable<VarChar>,
        amount -> Double,
        currency -> Nullable<VarChar>,
        state -> VarChar,
        message -> Nullable<Text>,
        invoice_url -> Nullable<VarChar>,
        return_url -> Nullable<VarChar>,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        // 014 enhancement
        out_order_id -> Nullable<VarChar>,
        pay_url -> Nullable<VarChar>,
    }
}

diesel::table! {
    transactions (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> VarChar,
        description -> Nullable<Text>,
        provider_id -> Nullable<VarChar>,
        category -> Nullable<VarChar>,
        transaction_type -> VarChar,
        product_id -> Nullable<VarChar>,
        user_id -> Nullable<VarChar>,
        application -> Nullable<VarChar>,
        amount -> Double,
        currency -> Nullable<VarChar>,
        balance -> Double,
        state -> VarChar,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

// ---------------------------------------------------------------------------
// Orders, tickets, forms (009)
// ---------------------------------------------------------------------------

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    orders (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> Nullable<VarChar>,
        provider -> Nullable<VarChar>,
        product_name -> Nullable<VarChar>,
        product_display_name -> Nullable<VarChar>,
        quantity -> Integer,
        price -> Double,
        currency -> VarChar,
        state -> VarChar,
        tag -> Nullable<VarChar>,
        invoice_url -> Nullable<Text>,
        payment_id -> Nullable<VarChar>,
        payment_name -> Nullable<VarChar>,
        return_url -> Nullable<Text>,
        #[sql_name = "user"]
        user_ -> Nullable<VarChar>,
        plan_name -> Nullable<VarChar>,
        pricing_name -> Nullable<VarChar>,
        error_text -> Nullable<Text>,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    tickets (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> Nullable<VarChar>,
        ticket_type -> VarChar,
        subject -> VarChar,
        content -> Nullable<Text>,
        status -> VarChar,
        priority -> VarChar,
        assignee -> Nullable<VarChar>,
        reporter -> Nullable<VarChar>,
        comments -> Nullable<Jsonb>,
        tags -> Nullable<Jsonb>,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    forms (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> Nullable<VarChar>,
        form_items -> Nullable<Jsonb>,
        is_enabled -> Bool,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

// ---------------------------------------------------------------------------
// Rules & sites (012)
// ---------------------------------------------------------------------------

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    rules (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        rule_type -> VarChar,
        expressions -> Jsonb,
        action -> VarChar,
        status_code -> Integer,
        reason -> VarChar,
        is_verbose -> Bool,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    sites (id) {
        id -> VarChar,
        owner -> VarChar,
        name -> VarChar,
        display_name -> Nullable<VarChar>,
        tag -> Nullable<VarChar>,
        domain -> VarChar,
        other_domains -> Nullable<Jsonb>,
        need_redirect -> Bool,
        disable_verbose -> Bool,
        rules -> Nullable<Jsonb>,
        enable_alert -> Bool,
        alert_interval -> Integer,
        alert_try_times -> Integer,
        alert_providers -> Nullable<Jsonb>,
        challenges -> Nullable<Jsonb>,
        host -> Nullable<VarChar>,
        port -> Integer,
        hosts -> Nullable<Jsonb>,
        ssl_mode -> VarChar,
        ssl_cert -> Nullable<VarChar>,
        public_ip -> Nullable<VarChar>,
        node -> Nullable<VarChar>,
        status -> VarChar,
        nodes -> Nullable<Jsonb>,
        casdoor_application -> Nullable<VarChar>,
        is_deleted -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

// ---------------------------------------------------------------------------
// Consent records (013)
// ---------------------------------------------------------------------------

diesel::table! {
    use diesel::sql_types::*;
    use diesel::pg::sql_types::*;

    consent_records (id) {
        id -> VarChar,
        user_id -> VarChar,
        application_id -> VarChar,
        granted_scopes -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

// ---------------------------------------------------------------------------
// Foreign key relationships
// ---------------------------------------------------------------------------

diesel::joinable!(user_roles -> users (user_id));
diesel::joinable!(user_roles -> roles (role_id));
diesel::joinable!(role_permissions -> roles (role_id));
diesel::joinable!(role_permissions -> permissions (permission_id));
diesel::joinable!(user_groups -> users (user_id));
diesel::joinable!(user_groups -> groups (group_id));
diesel::joinable!(user_provider_links -> users (user_id));
diesel::joinable!(user_mfa -> users (user_id));
diesel::joinable!(user_webauthn_credentials -> users (user_id));
diesel::joinable!(casbin_enforcers -> casbin_models (model_id));
diesel::joinable!(casbin_enforcers -> casbin_adapters (adapter_id));
diesel::joinable!(consent_records -> users (user_id));
diesel::joinable!(consent_records -> applications (application_id));

diesel::allow_tables_to_appear_in_same_query!(
    organizations,
    users,
    applications,
    roles,
    user_roles,
    permissions,
    role_permissions,
    casbin_rule,
    providers,
    tokens,
    groups,
    user_groups,
    sessions,
    certificates,
    resources,
    webhooks,
    syncers,
    verifications,
    invitations,
    records,
    user_provider_links,
    user_mfa,
    user_webauthn_credentials,
    casbin_models,
    casbin_adapters,
    casbin_enforcers,
    products,
    plans,
    pricings,
    subscriptions,
    payments,
    transactions,
    orders,
    tickets,
    forms,
    rules,
    sites,
    consent_records,
);

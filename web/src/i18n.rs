use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Locale {
    En,
    Zh,
    Es,
    Fr,
    De,
    Ja,
    Ko,
    Ru,
}

impl Locale {
    pub fn label(self) -> &'static str {
        match self {
            Locale::En => "English",
            Locale::Zh => "\u{4e2d}\u{6587}",
            Locale::Es => "Espa\u{f1}ol",
            Locale::Fr => "Fran\u{e7}ais",
            Locale::De => "Deutsch",
            Locale::Ja => "\u{65e5}\u{672c}\u{8a9e}",
            Locale::Ko => "\u{d55c}\u{ad6d}\u{c5b4}",
            Locale::Ru => "\u{0420}\u{0443}\u{0441}\u{0441}\u{043a}\u{0438}\u{0439}",
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Zh => "zh",
            Locale::Es => "es",
            Locale::Fr => "fr",
            Locale::De => "de",
            Locale::Ja => "ja",
            Locale::Ko => "ko",
            Locale::Ru => "ru",
        }
    }

    pub fn all() -> &'static [Locale] {
        &[
            Locale::En,
            Locale::Zh,
            Locale::Es,
            Locale::Fr,
            Locale::De,
            Locale::Ja,
            Locale::Ko,
            Locale::Ru,
        ]
    }

    pub fn from_code(code: &str) -> Option<Locale> {
        match code {
            "en" => Some(Locale::En),
            "zh" => Some(Locale::Zh),
            "es" => Some(Locale::Es),
            "fr" => Some(Locale::Fr),
            "de" => Some(Locale::De),
            "ja" => Some(Locale::Ja),
            "ko" => Some(Locale::Ko),
            "ru" => Some(Locale::Ru),
            _ => None,
        }
    }
}

impl Default for Locale {
    fn default() -> Self {
        Locale::En
    }
}

/// Translate a key to the given locale. Falls back to English if no translation exists.
pub fn t(key: &str, locale: Locale) -> &'static str {
    match locale {
        Locale::Zh => zh(key).unwrap_or_else(|| en(key)),
        _ => en(key),
    }
}

fn en(key: &str) -> &'static str {
    match key {
        // Common
        "app.name" => "Casdog",
        "common.loading" => "Loading...",
        "common.save" => "Save",
        "common.cancel" => "Cancel",
        "common.delete" => "Delete",
        "common.edit" => "Edit",
        "common.create" => "Create",
        "common.search" => "Search",
        "common.filter" => "Filter",
        "common.refresh" => "Refresh",
        "common.back" => "Back",
        "common.next" => "Next",
        "common.previous" => "Previous",
        "common.submit" => "Submit",
        "common.close" => "Close",
        "common.yes" => "Yes",
        "common.no" => "No",
        "common.confirm" => "Confirm",
        "common.required" => "Required",
        "common.optional" => "Optional",
        "common.actions" => "Actions",
        "common.status" => "Status",
        "common.enabled" => "Enabled",
        "common.disabled" => "Disabled",
        "common.success" => "Success",
        "common.error" => "Error",
        "common.warning" => "Warning",
        "common.or" => "or",

        // Login
        "login.title" => "Sign in",
        "login.subtitle" => "Sign in to your account to continue.",
        "login.organization" => "Organization",
        "login.username" => "Username",
        "login.password" => "Password",
        "login.sign_in" => "Sign in",
        "login.signing_in" => "Signing in...",
        "login.sign_up_link" => "Sign up",
        "login.forgot_password" => "Forgot password?",
        "login.no_account" => "Don't have an account?",
        "login.social_heading" => "Or sign in with",
        "login.error_invalid" => "Invalid username or password.",
        "login.remember_me" => "Remember me",

        // Signup
        "signup.title" => "Create account",
        "signup.subtitle" => "Register a new account to get started.",
        "signup.organization" => "Organization",
        "signup.username" => "Username",
        "signup.display_name" => "Display name",
        "signup.email" => "Email",
        "signup.phone" => "Phone",
        "signup.password" => "Password",
        "signup.confirm_password" => "Confirm password",
        "signup.application" => "Application",
        "signup.submit" => "Create account",
        "signup.creating" => "Creating account...",
        "signup.have_account" => "Already have an account?",
        "signup.sign_in_link" => "Sign in",
        "signup.password_mismatch" => "Passwords do not match.",

        // Authorize
        "authorize.title" => "Authorize application",
        "authorize.subtitle" => "An application is requesting access to your account.",
        "authorize.scopes" => "Requested permissions",
        "authorize.signed_in_as" => "Signed in as",
        "authorize.allow" => "Allow",
        "authorize.deny" => "Deny",
        "authorize.allowing" => "Authorizing...",
        "authorize.app_wants_access" => "wants to access your account",

        // Consent
        "consent.title" => "Consent management",
        "consent.subtitle" => "Manage your application authorizations.",
        "consent.granted_list" => "Granted consents",
        "consent.no_consents" => "No consents granted yet.",
        "consent.revoke" => "Revoke",
        "consent.revoking" => "Revoking...",
        "consent.grant_new" => "Grant new consent",
        "consent.application" => "Application",
        "consent.scopes" => "Scopes",
        "consent.granted_at" => "Granted at",
        "consent.grant" => "Grant",

        // Device auth
        "device_auth.title" => "Device authorization",
        "device_auth.subtitle" => "Enter the code shown on your device to authorize it.",
        "device_auth.user_code" => "User code",
        "device_auth.user_code_placeholder" => "ABCD-1234",
        "device_auth.verify" => "Verify",
        "device_auth.verifying" => "Verifying...",
        "device_auth.approve" => "Approve",
        "device_auth.deny" => "Deny",
        "device_auth.status_pending" => "Waiting for verification...",
        "device_auth.status_verified" => "Code verified. Approve or deny this device.",
        "device_auth.status_approved" => "Device authorized successfully.",
        "device_auth.status_denied" => "Authorization denied.",

        // Account
        "account.title" => "Account settings",
        "account.subtitle" => "Manage your profile, security, and sessions.",
        "account.profile" => "Profile",
        "account.display_name" => "Display name",
        "account.avatar" => "Avatar URL",
        "account.email" => "Email",
        "account.phone" => "Phone",
        "account.bio" => "Bio",
        "account.save_profile" => "Save profile",
        "account.saving" => "Saving...",
        "account.security" => "Security",
        "account.current_password" => "Current password",
        "account.new_password" => "New password",
        "account.confirm_new_password" => "Confirm new password",
        "account.change_password" => "Change password",
        "account.changing_password" => "Changing...",
        "account.mfa" => "Multi-factor authentication",
        "account.mfa_totp" => "Authenticator app (TOTP)",
        "account.mfa_enable" => "Enable MFA",
        "account.mfa_disable" => "Disable MFA",
        "account.mfa_scan_qr" => "Scan this QR code with your authenticator app",
        "account.mfa_enter_code" => "Enter verification code",
        "account.mfa_verify" => "Verify and enable",
        "account.mfa_recovery_codes" => "Recovery codes",
        "account.mfa_recovery_warning" => "Save these codes in a secure place. Each code can only be used once.",
        "account.webauthn" => "WebAuthn / Passkeys",
        "account.webauthn_register" => "Register new credential",
        "account.webauthn_no_credentials" => "No credentials registered.",
        "account.webauthn_name" => "Credential name",
        "account.webauthn_registered" => "Registered",
        "account.webauthn_remove" => "Remove",
        "account.sessions" => "Active sessions",
        "account.sessions_current" => "Current session",
        "account.sessions_revoke" => "Revoke",
        "account.sessions_revoke_all" => "Revoke all other sessions",
        "account.sessions_no_others" => "No other active sessions.",

        // Result
        "result.title_success" => "Action completed",
        "result.title_failure" => "Action failed",
        "result.transaction_id" => "Transaction ID",
        "result.amount" => "Amount",
        "result.provider" => "Provider",
        "result.back_home" => "Back to home",
        "result.try_again" => "Try again",

        // Forgot password
        "forgot.title" => "Reset your password",
        "forgot.subtitle" => "Enter your email address to receive a verification code.",
        "forgot.email" => "Email address",
        "forgot.send_code" => "Send code",
        "forgot.sending" => "Sending...",
        "forgot.code" => "Verification code",
        "forgot.new_password" => "New password",
        "forgot.confirm_password" => "Confirm new password",
        "forgot.reset" => "Reset password",
        "forgot.resetting" => "Resetting...",
        "forgot.back_to_login" => "Back to sign in",
        "forgot.code_sent" => "Verification code sent to your email.",
        "forgot.password_mismatch" => "Passwords do not match.",
        "forgot.reset_success" => "Password reset successfully. You can now sign in.",

        // Form fields
        "field.show_password" => "Show",
        "field.hide_password" => "Hide",
        "field.json_valid" => "Valid JSON",
        "field.json_invalid" => "Invalid JSON",
        "field.tags_hint" => "Press Enter to add a tag",

        // CAPTCHA
        "captcha.title" => "Verification",
        "captcha.instructions" => "Complete the verification to continue.",
        "captcha.placeholder" => "Enter the code above",
        "captcha.refresh" => "Get new code",
        "captcha.verify" => "Verify",

        // Resource form
        "resource_form.json_editor" => "JSON editor",
        "resource_form.structured" => "Structured editor",
        "resource_form.toggle_view" => "Toggle view",

        _ => key,
    }
}

fn zh(key: &str) -> Option<&'static str> {
    Some(match key {
        // Common
        "app.name" => "Casdog",
        "common.loading" => "\u{52a0}\u{8f7d}\u{4e2d}...",
        "common.save" => "\u{4fdd}\u{5b58}",
        "common.cancel" => "\u{53d6}\u{6d88}",
        "common.delete" => "\u{5220}\u{9664}",
        "common.edit" => "\u{7f16}\u{8f91}",
        "common.create" => "\u{521b}\u{5efa}",
        "common.search" => "\u{641c}\u{7d22}",
        "common.filter" => "\u{7b5b}\u{9009}",
        "common.refresh" => "\u{5237}\u{65b0}",
        "common.back" => "\u{8fd4}\u{56de}",
        "common.next" => "\u{4e0b}\u{4e00}\u{6b65}",
        "common.previous" => "\u{4e0a}\u{4e00}\u{6b65}",
        "common.submit" => "\u{63d0}\u{4ea4}",
        "common.close" => "\u{5173}\u{95ed}",
        "common.yes" => "\u{662f}",
        "common.no" => "\u{5426}",
        "common.confirm" => "\u{786e}\u{8ba4}",
        "common.required" => "\u{5fc5}\u{586b}",
        "common.optional" => "\u{53ef}\u{9009}",
        "common.actions" => "\u{64cd}\u{4f5c}",
        "common.status" => "\u{72b6}\u{6001}",
        "common.enabled" => "\u{5df2}\u{542f}\u{7528}",
        "common.disabled" => "\u{5df2}\u{7981}\u{7528}",
        "common.success" => "\u{6210}\u{529f}",
        "common.error" => "\u{9519}\u{8bef}",
        "common.warning" => "\u{8b66}\u{544a}",
        "common.or" => "\u{6216}",

        // Login
        "login.title" => "\u{767b}\u{5f55}",
        "login.subtitle" => "\u{767b}\u{5f55}\u{60a8}\u{7684}\u{8d26}\u{6237}\u{4ee5}\u{7ee7}\u{7eed}\u{3002}",
        "login.organization" => "\u{7ec4}\u{7ec7}",
        "login.username" => "\u{7528}\u{6237}\u{540d}",
        "login.password" => "\u{5bc6}\u{7801}",
        "login.sign_in" => "\u{767b}\u{5f55}",
        "login.signing_in" => "\u{767b}\u{5f55}\u{4e2d}...",
        "login.sign_up_link" => "\u{6ce8}\u{518c}",
        "login.forgot_password" => "\u{5fd8}\u{8bb0}\u{5bc6}\u{7801}\u{ff1f}",
        "login.no_account" => "\u{6ca1}\u{6709}\u{8d26}\u{6237}\u{ff1f}",
        "login.social_heading" => "\u{6216}\u{901a}\u{8fc7}\u{4ee5}\u{4e0b}\u{65b9}\u{5f0f}\u{767b}\u{5f55}",
        "login.error_invalid" => "\u{7528}\u{6237}\u{540d}\u{6216}\u{5bc6}\u{7801}\u{65e0}\u{6548}\u{3002}",
        "login.remember_me" => "\u{8bb0}\u{4f4f}\u{6211}",

        // Signup
        "signup.title" => "\u{521b}\u{5efa}\u{8d26}\u{6237}",
        "signup.subtitle" => "\u{6ce8}\u{518c}\u{65b0}\u{8d26}\u{6237}\u{4ee5}\u{5f00}\u{59cb}\u{4f7f}\u{7528}\u{3002}",
        "signup.organization" => "\u{7ec4}\u{7ec7}",
        "signup.username" => "\u{7528}\u{6237}\u{540d}",
        "signup.display_name" => "\u{663e}\u{793a}\u{540d}\u{79f0}",
        "signup.email" => "\u{7535}\u{5b50}\u{90ae}\u{4ef6}",
        "signup.phone" => "\u{7535}\u{8bdd}",
        "signup.password" => "\u{5bc6}\u{7801}",
        "signup.confirm_password" => "\u{786e}\u{8ba4}\u{5bc6}\u{7801}",
        "signup.application" => "\u{5e94}\u{7528}",
        "signup.submit" => "\u{521b}\u{5efa}\u{8d26}\u{6237}",
        "signup.creating" => "\u{521b}\u{5efa}\u{4e2d}...",
        "signup.have_account" => "\u{5df2}\u{6709}\u{8d26}\u{6237}\u{ff1f}",
        "signup.sign_in_link" => "\u{767b}\u{5f55}",
        "signup.password_mismatch" => "\u{5bc6}\u{7801}\u{4e0d}\u{5339}\u{914d}\u{3002}",

        // Authorize
        "authorize.title" => "\u{6388}\u{6743}\u{5e94}\u{7528}",
        "authorize.subtitle" => "\u{4e00}\u{4e2a}\u{5e94}\u{7528}\u{6b63}\u{5728}\u{8bf7}\u{6c42}\u{8bbf}\u{95ee}\u{60a8}\u{7684}\u{8d26}\u{6237}\u{3002}",
        "authorize.scopes" => "\u{8bf7}\u{6c42}\u{7684}\u{6743}\u{9650}",
        "authorize.signed_in_as" => "\u{5df2}\u{767b}\u{5f55}\u{4e3a}",
        "authorize.allow" => "\u{5141}\u{8bb8}",
        "authorize.deny" => "\u{62d2}\u{7edd}",
        "authorize.allowing" => "\u{6388}\u{6743}\u{4e2d}...",
        "authorize.app_wants_access" => "\u{8bf7}\u{6c42}\u{8bbf}\u{95ee}\u{60a8}\u{7684}\u{8d26}\u{6237}",

        // Consent
        "consent.title" => "\u{6388}\u{6743}\u{7ba1}\u{7406}",
        "consent.subtitle" => "\u{7ba1}\u{7406}\u{60a8}\u{7684}\u{5e94}\u{7528}\u{6388}\u{6743}\u{3002}",
        "consent.granted_list" => "\u{5df2}\u{6388}\u{6743}\u{5217}\u{8868}",
        "consent.no_consents" => "\u{5c1a}\u{672a}\u{6388}\u{4e88}\u{4efb}\u{4f55}\u{6388}\u{6743}\u{3002}",
        "consent.revoke" => "\u{64a4}\u{9500}",
        "consent.revoking" => "\u{64a4}\u{9500}\u{4e2d}...",
        "consent.grant_new" => "\u{6388}\u{4e88}\u{65b0}\u{6388}\u{6743}",
        "consent.application" => "\u{5e94}\u{7528}",
        "consent.scopes" => "\u{6743}\u{9650}",
        "consent.granted_at" => "\u{6388}\u{6743}\u{65f6}\u{95f4}",
        "consent.grant" => "\u{6388}\u{6743}",

        // Device auth
        "device_auth.title" => "\u{8bbe}\u{5907}\u{6388}\u{6743}",
        "device_auth.subtitle" => "\u{8f93}\u{5165}\u{8bbe}\u{5907}\u{4e0a}\u{663e}\u{793a}\u{7684}\u{4ee3}\u{7801}\u{4ee5}\u{6388}\u{6743}\u{3002}",
        "device_auth.user_code" => "\u{7528}\u{6237}\u{4ee3}\u{7801}",
        "device_auth.verify" => "\u{9a8c}\u{8bc1}",
        "device_auth.verifying" => "\u{9a8c}\u{8bc1}\u{4e2d}...",
        "device_auth.approve" => "\u{6279}\u{51c6}",
        "device_auth.deny" => "\u{62d2}\u{7edd}",
        "device_auth.status_pending" => "\u{7b49}\u{5f85}\u{9a8c}\u{8bc1}...",
        "device_auth.status_verified" => "\u{4ee3}\u{7801}\u{5df2}\u{9a8c}\u{8bc1}\u{3002}\u{8bf7}\u{6279}\u{51c6}\u{6216}\u{62d2}\u{7edd}\u{6b64}\u{8bbe}\u{5907}\u{3002}",
        "device_auth.status_approved" => "\u{8bbe}\u{5907}\u{6388}\u{6743}\u{6210}\u{529f}\u{3002}",
        "device_auth.status_denied" => "\u{6388}\u{6743}\u{5df2}\u{62d2}\u{7edd}\u{3002}",

        // Account
        "account.title" => "\u{8d26}\u{6237}\u{8bbe}\u{7f6e}",
        "account.subtitle" => "\u{7ba1}\u{7406}\u{60a8}\u{7684}\u{4e2a}\u{4eba}\u{8d44}\u{6599}\u{3001}\u{5b89}\u{5168}\u{548c}\u{4f1a}\u{8bdd}\u{3002}",
        "account.profile" => "\u{4e2a}\u{4eba}\u{8d44}\u{6599}",
        "account.display_name" => "\u{663e}\u{793a}\u{540d}\u{79f0}",
        "account.avatar" => "\u{5934}\u{50cf} URL",
        "account.email" => "\u{7535}\u{5b50}\u{90ae}\u{4ef6}",
        "account.phone" => "\u{7535}\u{8bdd}",
        "account.bio" => "\u{7b80}\u{4ecb}",
        "account.save_profile" => "\u{4fdd}\u{5b58}\u{8d44}\u{6599}",
        "account.saving" => "\u{4fdd}\u{5b58}\u{4e2d}...",
        "account.security" => "\u{5b89}\u{5168}",
        "account.current_password" => "\u{5f53}\u{524d}\u{5bc6}\u{7801}",
        "account.new_password" => "\u{65b0}\u{5bc6}\u{7801}",
        "account.confirm_new_password" => "\u{786e}\u{8ba4}\u{65b0}\u{5bc6}\u{7801}",
        "account.change_password" => "\u{4fee}\u{6539}\u{5bc6}\u{7801}",
        "account.changing_password" => "\u{4fee}\u{6539}\u{4e2d}...",
        "account.mfa" => "\u{591a}\u{56e0}\u{7d20}\u{8ba4}\u{8bc1}",
        "account.mfa_totp" => "\u{9a8c}\u{8bc1}\u{5668}\u{5e94}\u{7528} (TOTP)",
        "account.mfa_enable" => "\u{542f}\u{7528} MFA",
        "account.mfa_disable" => "\u{7981}\u{7528} MFA",
        "account.mfa_scan_qr" => "\u{4f7f}\u{7528}\u{9a8c}\u{8bc1}\u{5668}\u{5e94}\u{7528}\u{626b}\u{63cf}\u{6b64}\u{4e8c}\u{7ef4}\u{7801}",
        "account.mfa_enter_code" => "\u{8f93}\u{5165}\u{9a8c}\u{8bc1}\u{7801}",
        "account.mfa_verify" => "\u{9a8c}\u{8bc1}\u{5e76}\u{542f}\u{7528}",
        "account.mfa_recovery_codes" => "\u{6062}\u{590d}\u{4ee3}\u{7801}",
        "account.mfa_recovery_warning" => "\u{8bf7}\u{5c06}\u{8fd9}\u{4e9b}\u{4ee3}\u{7801}\u{4fdd}\u{5b58}\u{5728}\u{5b89}\u{5168}\u{7684}\u{5730}\u{65b9}\u{3002}\u{6bcf}\u{4e2a}\u{4ee3}\u{7801}\u{53ea}\u{80fd}\u{4f7f}\u{7528}\u{4e00}\u{6b21}\u{3002}",
        "account.webauthn" => "WebAuthn / \u{901a}\u{884c}\u{5bc6}\u{94a5}",
        "account.webauthn_register" => "\u{6ce8}\u{518c}\u{65b0}\u{51ed}\u{8bc1}",
        "account.webauthn_no_credentials" => "\u{5c1a}\u{672a}\u{6ce8}\u{518c}\u{51ed}\u{8bc1}\u{3002}",
        "account.sessions" => "\u{6d3b}\u{8dc3}\u{4f1a}\u{8bdd}",
        "account.sessions_current" => "\u{5f53}\u{524d}\u{4f1a}\u{8bdd}",
        "account.sessions_revoke" => "\u{64a4}\u{9500}",
        "account.sessions_revoke_all" => "\u{64a4}\u{9500}\u{6240}\u{6709}\u{5176}\u{4ed6}\u{4f1a}\u{8bdd}",
        "account.sessions_no_others" => "\u{6ca1}\u{6709}\u{5176}\u{4ed6}\u{6d3b}\u{8dc3}\u{4f1a}\u{8bdd}\u{3002}",

        // Result
        "result.title_success" => "\u{64cd}\u{4f5c}\u{5b8c}\u{6210}",
        "result.title_failure" => "\u{64cd}\u{4f5c}\u{5931}\u{8d25}",
        "result.transaction_id" => "\u{4ea4}\u{6613} ID",
        "result.amount" => "\u{91d1}\u{989d}",
        "result.provider" => "\u{63d0}\u{4f9b}\u{5546}",
        "result.back_home" => "\u{8fd4}\u{56de}\u{9996}\u{9875}",
        "result.try_again" => "\u{91cd}\u{8bd5}",

        // Forgot password
        "forgot.title" => "\u{91cd}\u{7f6e}\u{5bc6}\u{7801}",
        "forgot.subtitle" => "\u{8f93}\u{5165}\u{60a8}\u{7684}\u{7535}\u{5b50}\u{90ae}\u{4ef6}\u{5730}\u{5740}\u{4ee5}\u{63a5}\u{6536}\u{9a8c}\u{8bc1}\u{7801}\u{3002}",
        "forgot.email" => "\u{7535}\u{5b50}\u{90ae}\u{4ef6}\u{5730}\u{5740}",
        "forgot.send_code" => "\u{53d1}\u{9001}\u{9a8c}\u{8bc1}\u{7801}",
        "forgot.sending" => "\u{53d1}\u{9001}\u{4e2d}...",
        "forgot.code" => "\u{9a8c}\u{8bc1}\u{7801}",
        "forgot.new_password" => "\u{65b0}\u{5bc6}\u{7801}",
        "forgot.confirm_password" => "\u{786e}\u{8ba4}\u{65b0}\u{5bc6}\u{7801}",
        "forgot.reset" => "\u{91cd}\u{7f6e}\u{5bc6}\u{7801}",
        "forgot.resetting" => "\u{91cd}\u{7f6e}\u{4e2d}...",
        "forgot.back_to_login" => "\u{8fd4}\u{56de}\u{767b}\u{5f55}",
        "forgot.code_sent" => "\u{9a8c}\u{8bc1}\u{7801}\u{5df2}\u{53d1}\u{9001}\u{5230}\u{60a8}\u{7684}\u{90ae}\u{7bb1}\u{3002}",
        "forgot.password_mismatch" => "\u{5bc6}\u{7801}\u{4e0d}\u{5339}\u{914d}\u{3002}",
        "forgot.reset_success" => "\u{5bc6}\u{7801}\u{91cd}\u{7f6e}\u{6210}\u{529f}\u{3002}\u{60a8}\u{73b0}\u{5728}\u{53ef}\u{4ee5}\u{767b}\u{5f55}\u{3002}",

        // Form fields
        "field.show_password" => "\u{663e}\u{793a}",
        "field.hide_password" => "\u{9690}\u{85cf}",
        "field.json_valid" => "JSON \u{6709}\u{6548}",
        "field.json_invalid" => "JSON \u{65e0}\u{6548}",
        "field.tags_hint" => "\u{6309}\u{56de}\u{8f66}\u{6dfb}\u{52a0}\u{6807}\u{7b7e}",

        // CAPTCHA
        "captcha.title" => "\u{9a8c}\u{8bc1}",
        "captcha.instructions" => "\u{5b8c}\u{6210}\u{9a8c}\u{8bc1}\u{4ee5}\u{7ee7}\u{7eed}\u{3002}",
        "captcha.placeholder" => "\u{8f93}\u{5165}\u{4e0a}\u{65b9}\u{7684}\u{4ee3}\u{7801}",
        "captcha.refresh" => "\u{83b7}\u{53d6}\u{65b0}\u{4ee3}\u{7801}",
        "captcha.verify" => "\u{9a8c}\u{8bc1}",

        // Resource form
        "resource_form.json_editor" => "JSON \u{7f16}\u{8f91}\u{5668}",
        "resource_form.structured" => "\u{7ed3}\u{6784}\u{5316}\u{7f16}\u{8f91}\u{5668}",
        "resource_form.toggle_view" => "\u{5207}\u{6362}\u{89c6}\u{56fe}",

        _ => return None,
    })
}

/// Returns a reactive signal holding the current Locale.
/// Call this once at the top level of your app and pass the signal down.
pub fn use_locale() -> Signal<Locale> {
    use_signal(|| {
        gloo_storage::LocalStorage::get::<String>("casdog.locale")
            .ok()
            .and_then(|code| Locale::from_code(&code))
            .unwrap_or(Locale::En)
    })
}

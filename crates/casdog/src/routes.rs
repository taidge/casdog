use rust_embed::Embed;
use salvo::oapi::OpenApi;
use salvo::prelude::*;
use salvo::serve_static::static_embed;

use crate::handlers::{
    adapter, app_extra, application, auth, cas, casbin_cli, cert, cert_extra, consent, dashboard,
    enforcer, form, group, health, impersonation, invitation, ldap, login_compat, messaging, mfa,
    model, oidc, order, org_extra, organization, payment, permission, permission_extra, plan,
    policy, pricing, product, provider, provider_extra, record, resource, role, rule, saml, scim,
    session, site, social_login, subscription, syncer, system, ticket, token, transaction, upload,
    user, user_extra, verification, webauthn, webhook,
};
use crate::hoops::{AutoSigninFilter, JwtAuth, OptionalJwtAuth};

#[derive(Embed)]
#[folder = "$CASDOG_WEB_DIST"]
struct Assets;

pub fn create_router() -> Router {
    Router::new()
        .push(wellknown_router())
        .push(cas_root_router())
        .push(api_router())
        .push(oauth_router())
        .push(swagger_router())
        .push(static_router())
}

fn static_router() -> Router {
    Router::new()
        .push(Router::with_path("{**path}").get(static_embed::<Assets>().fallback("index.html")))
}

fn wellknown_router() -> Router {
    Router::with_path(".well-known")
        .push(Router::with_path("openid-configuration").get(oidc::openid_configuration))
        .push(Router::with_path("oauth-authorization-server").get(oidc::oauth_server_metadata))
        .push(
            Router::with_path("oauth-protected-resource")
                .get(oidc::oauth_protected_resource_metadata),
        )
        .push(Router::with_path("jwks").get(oidc::jwks))
        .push(Router::with_path("webfinger").get(oidc::webfinger))
        .push(
            Router::with_path("{application}/openid-configuration")
                .get(oidc::app_openid_configuration),
        )
        .push(
            Router::with_path("{application}/oauth-authorization-server")
                .get(oidc::app_oauth_server_metadata),
        )
        .push(
            Router::with_path("{application}/oauth-protected-resource")
                .get(oidc::app_oauth_protected_resource_metadata),
        )
        .push(Router::with_path("{application}/jwks").get(oidc::app_jwks))
        .push(Router::with_path("{application}/webfinger").get(oidc::app_webfinger))
}

fn oauth_router() -> Router {
    Router::with_path("login/oauth")
        .push(Router::with_path("authorize").get(oidc::authorize))
        .push(Router::with_path("access_token").post(auth::oauth_access_token))
        .push(Router::with_path("refresh_token").post(auth::oauth_refresh_token))
        .push(Router::with_path("introspect").post(auth::oauth_introspect))
        .push(Router::with_path("revoke").post(auth::oauth_revoke))
}

fn public_webauthn_routes() -> Router {
    Router::with_path("webauthn")
        .push(Router::with_path("signin/begin").get(webauthn::signin_begin))
        .push(Router::with_path("signin/finish").post(webauthn::signin_finish))
}

fn protected_webauthn_routes() -> Router {
    Router::with_path("webauthn")
        .push(Router::with_path("signup/begin").get(webauthn::signup_begin))
        .push(Router::with_path("signup/finish").post(webauthn::signup_finish))
        .push(Router::with_path("credentials").get(webauthn::list_credentials))
        .push(Router::with_path("credentials/{id}").delete(webauthn::delete_credential))
}

fn cas_root_router() -> Router {
    Router::with_path("cas/{organization}/{application}")
        .push(Router::with_path("serviceValidate").get(cas::service_validate))
        .push(Router::with_path("proxyValidate").get(cas::proxy_validate))
        .push(Router::with_path("proxy").get(cas::proxy))
        .push(Router::with_path("validate").get(cas::validate))
        .push(Router::with_path("p3/serviceValidate").get(cas::service_validate))
        .push(Router::with_path("p3/proxyValidate").get(cas::proxy_validate))
        .push(Router::with_path("samlValidate").post(cas::saml_validate))
}

fn api_router() -> Router {
    Router::with_path("api")
        .push(public_routes())
        .push(protected_routes())
}

fn public_routes() -> Router {
    Router::new()
        .push(Router::with_path("health").get(health::health_check))
        .push(Router::with_path("signup").post(auth::signup))
        .push(Router::with_path("login").post(auth::login))
        .push(Router::with_path("get-app-login").get(auth::get_app_login))
        .push(Router::with_path("userinfo").get(oidc::userinfo))
        .push(Router::with_path("captcha").get(verification::get_captcha))
        .push(Router::with_path("get-captcha-status").get(auth::get_captcha_status))
        .push(Router::with_path("verify-captcha").post(verification::verify_captcha))
        .push(Router::with_path("get-email-and-phone").post(verification::get_email_and_phone))
        .push(Router::with_path("callback").get(auth::callback).post(auth::callback))
        .push(Router::with_path("device-auth").post(auth::device_auth))
        .push(Router::with_path("kerberos-login").get(login_compat::kerberos_login))
        .push(Router::with_path("oauth/register").post(auth::oauth_register))
        .push(Router::with_path("get-qrcode").get(auth::get_qrcode))
        .push(Router::with_path("get-webhook-event").get(auth::get_webhook_event))
        .push(Router::with_path("faceid-signin-begin").get(login_compat::faceid_signin_begin))
        .push(Router::with_path("faceid-signin-finish").post(login_compat::faceid_signin_finish))
        .push(
            Router::new()
                .hoop(OptionalJwtAuth)
                .push(Router::with_path("send-email").post(messaging::send_email))
                .push(Router::with_path("send-sms").post(messaging::send_sms))
                .push(Router::with_path("send-notification").post(messaging::send_notification)),
        )
        .push(public_webauthn_routes())
        .push(saml_routes())
        .push(Router::with_path("get-saml-login").get(saml::get_saml_login))
        .push(Router::with_path("acs").post(saml::saml_acs).get(saml::saml_acs))
        .push(
            Router::with_path("saml/redirect/{owner}/{application}")
                .hoop(AutoSigninFilter)
                .get(saml::saml_redirect),
        )
        // Social login (OAuth provider callbacks)
        .push(Router::with_path("auth/{provider}").get(social_login::get_provider_auth_url))
        .push(Router::with_path("auth/{provider}/callback").get(social_login::provider_callback))
}

fn protected_routes() -> Router {
    Router::new()
        .hoop(JwtAuth)
        .push(Router::with_path("logout").get(auth::logout).post(auth::logout))
        .push(Router::with_path("get-account").get(auth::get_account))
        .push(Router::with_path("set-password").post(auth::set_password))
        .push(Router::with_path("check-user-password").post(auth::check_user_password))
        .push(Router::with_path("reset-email-or-phone").post(verification::reset_email_or_phone))
        .push(Router::with_path("grant-consent").post(consent::grant_consent))
        .push(Router::with_path("revoke-consent").post(consent::revoke_consent))
        .push(Router::with_path("sso-logout").get(auth::sso_logout).post(auth::sso_logout))
        .push(Router::with_path("unlink").post(social_login::unlink_provider_compat))
        .push(protected_webauthn_routes())
        // Social login provider unlink
        .push(Router::with_path("auth/{provider}/unlink").post(social_login::unlink_provider))
        .push(mfa_routes())
        .push(user_routes())
        .push(organization_routes())
        .push(application_routes())
        .push(role_routes())
        .push(permission_routes())
        .push(policy_routes())
        .push(provider_routes())
        .push(token_routes())
        .push(group_routes())
        .push(session_routes())
        .push(cert_routes())
        .push(resource_routes())
        .push(verification_routes())
        .push(webhook_routes())
        .push(syncer_routes())
        .push(invitation_routes())
        .push(record_routes())
        .push(cas_routes())
        .push(scim_routes())
        .push(ldap_routes())
        .push(model_routes())
        .push(adapter_routes())
        .push(enforcer_routes())
        .push(rule_routes())
        .push(site_routes())
        // Phase 8: Extra convenience query endpoints
        .push(Router::with_path("get-global-users").get(user_extra::get_global_users))
        .push(Router::with_path("get-sorted-users").get(user_extra::get_sorted_users))
        .push(Router::with_path("get-user-count").get(user_extra::get_user_count))
        .push(Router::with_path("get-organization-names").get(org_extra::get_organization_names))
        .push(Router::with_path("get-user-application").get(app_extra::get_user_application))
        .push(Router::with_path("get-organization-applications").get(app_extra::get_organization_applications))
        .push(Router::with_path("get-default-application").get(app_extra::get_default_application))
        .push(Router::with_path("get-global-providers").get(provider_extra::get_global_providers))
        .push(Router::with_path("get-global-certs").get(cert_extra::get_global_certs))
        .push(Router::with_path("get-global-rules").get(rule::get_global_rules))
        .push(Router::with_path("get-global-sites").get(site::get_global_sites))
        .push(Router::with_path("get-permissions-by-submitter").get(permission_extra::get_permissions_by_submitter))
        .push(Router::with_path("get-permissions-by-role").get(permission_extra::get_permissions_by_role))
        .push(Router::with_path("get-dashboard").get(dashboard::get_dashboard))
        .push(Router::with_path("metrics").get(dashboard::get_metrics))
        .push(Router::with_path("send-email").post(messaging::send_email))
        .push(Router::with_path("send-sms").post(messaging::send_sms))
        .push(Router::with_path("send-notification").post(messaging::send_notification))
        .push(Router::with_path("run-casbin-command").get(casbin_cli::run_casbin_command))
        .push(Router::with_path("refresh-engines").post(casbin_cli::refresh_engines))
        .push(Router::with_path("get-verifications").get(verification::list_verifications))
        .push(Router::with_path("get-verification").get(verification::get_verification_by_query))
        .push(Router::with_path("get-ldaps").get(ldap::get_ldaps))
        .push(Router::with_path("get-ldap").get(ldap::get_ldap))
        .push(Router::with_path("add-ldap").post(ldap::add_ldap))
        .push(Router::with_path("update-ldap").post(ldap::update_ldap))
        .push(Router::with_path("delete-ldap").post(ldap::delete_ldap))
        .push(Router::with_path("get-ldap-users").get(ldap::get_ldap_users))
        .push(Router::with_path("sync-ldap-users").post(ldap::sync_ldap_users))
        .push(Router::with_path("notify-payment").post(payment::notify_payment))
        .push(
            Router::with_path("notify-payment/{owner}/{payment}").post(payment::notify_payment),
        )
        .push(Router::with_path("invoice-payment").post(payment::invoice_payment))
        .push(Router::with_path("pay-order").post(order::pay_order))
        .push(Router::with_path("cancel-order").post(order::cancel_order))
        // System info
        .push(Router::with_path("get-system-info").get(system::get_system_info))
        .push(Router::with_path("get-version-info").get(system::get_version_info))
        .push(Router::with_path("get-prometheus-info").get(system::get_prometheus_info))
        // Impersonation
        .push(Router::with_path("impersonate-user").post(impersonation::impersonate_user))
        .push(Router::with_path("exit-impersonate-user").post(impersonation::exit_impersonate_user))
        // E-commerce
        .push(product_routes())
        .push(plan_routes())
        .push(pricing_routes())
        .push(subscription_routes())
        .push(payment_routes())
        .push(transaction_routes())
        .push(order_routes())
        .push(ticket_routes())
        .push(form_routes())
        .push(Router::with_path("upload-users").post(upload::upload_users))
        .push(Router::with_path("upload-groups").post(upload::upload_groups))
        .push(Router::with_path("upload-roles").post(upload::upload_roles))
        .push(Router::with_path("upload-permissions").post(upload::upload_permissions))
        // File upload/download/delete with storage provider integration
        .push(Router::with_path("upload-resource").post(upload::upload_resource))
        .push(Router::with_path("download-resource/{id}").get(upload::download_resource))
        .push(Router::with_path("delete-resource/{id}").post(upload::delete_resource_with_file))
}

fn user_routes() -> Router {
    Router::with_path("users")
        .get(user::list_users)
        .post(user::create_user)
        .push(
            Router::with_path("{id}")
                .get(user::get_user)
                .put(user::update_user)
                .delete(user::delete_user),
        )
}

fn organization_routes() -> Router {
    Router::with_path("organizations")
        .get(organization::list_organizations)
        .post(organization::create_organization)
        .push(
            Router::with_path("{id}")
                .get(organization::get_organization)
                .put(organization::update_organization)
                .delete(organization::delete_organization),
        )
}

fn application_routes() -> Router {
    Router::with_path("applications")
        .get(application::list_applications)
        .post(application::create_application)
        .push(
            Router::with_path("{id}")
                .get(application::get_application)
                .put(application::update_application)
                .delete(application::delete_application),
        )
}

fn role_routes() -> Router {
    Router::with_path("roles")
        .get(role::list_roles)
        .post(role::create_role)
        .push(Router::with_path("assign").post(role::assign_role))
        .push(Router::with_path("user/{user_id}").get(role::get_user_roles))
        .push(
            Router::with_path("{id}")
                .get(role::get_role)
                .put(role::update_role)
                .delete(role::delete_role),
        )
}

fn permission_routes() -> Router {
    Router::with_path("permissions")
        .get(permission::list_permissions)
        .post(permission::create_permission)
        .push(Router::with_path("assign").post(permission::assign_permission))
        .push(Router::with_path("role/{role_id}").get(permission::get_role_permissions))
        .push(
            Router::with_path("{id}")
                .get(permission::get_permission)
                .put(permission::update_permission)
                .delete(permission::delete_permission),
        )
}

fn policy_routes() -> Router {
    Router::new()
        .push(Router::with_path("enforce").post(policy::enforce))
        .push(Router::with_path("batch-enforce").post(policy::batch_enforce))
        .push(Router::with_path("get-all-objects").get(policy::get_all_objects))
        .push(Router::with_path("get-all-actions").get(policy::get_all_actions))
        .push(Router::with_path("get-all-roles").get(policy::get_all_roles))
        .push(
            Router::with_path("policies")
                .get(policy::get_policies)
                .post(policy::add_policy)
                .delete(policy::remove_policy),
        )
}

fn provider_routes() -> Router {
    Router::with_path("providers")
        .get(provider::list_providers)
        .post(provider::create_provider)
        .push(
            Router::with_path("{id}")
                .get(provider::get_provider)
                .put(provider::update_provider)
                .delete(provider::delete_provider),
        )
}

fn token_routes() -> Router {
    Router::with_path("tokens")
        .get(token::list_tokens)
        .post(token::create_token)
        .push(
            Router::with_path("{id}")
                .get(token::get_token)
                .put(token::update_token)
                .delete(token::delete_token),
        )
}

fn group_routes() -> Router {
    Router::with_path("groups")
        .get(group::list_groups)
        .post(group::create_group)
        .push(Router::with_path("add-user").post(group::add_user_to_group))
        .push(Router::with_path("remove-user").post(group::remove_user_from_group))
        .push(
            Router::with_path("{id}")
                .get(group::get_group)
                .put(group::update_group)
                .delete(group::delete_group),
        )
        .push(Router::with_path("{id}/users").get(group::get_users_in_group))
}

fn session_routes() -> Router {
    Router::with_path("sessions")
        .get(session::list_sessions)
        .post(session::create_session)
        .push(Router::with_path("is-duplicated").post(session::is_session_duplicated))
        .push(
            Router::with_path("{id}")
                .get(session::get_session)
                .put(session::update_session)
                .delete(session::delete_session),
        )
}

fn cert_routes() -> Router {
    Router::with_path("certs")
        .get(cert::list_certs)
        .post(cert::create_cert)
        .push(
            Router::with_path("{id}")
                .get(cert::get_cert)
                .put(cert::update_cert)
                .delete(cert::delete_cert),
        )
}

fn resource_routes() -> Router {
    Router::with_path("resources")
        .get(resource::list_resources)
        .post(resource::create_resource)
        .push(
            Router::with_path("{id}")
                .get(resource::get_resource)
                .put(resource::update_resource)
                .delete(resource::delete_resource),
        )
}

fn verification_routes() -> Router {
    Router::with_path("verification")
        .push(Router::with_path("send-code").post(verification::send_verification_code))
        .push(Router::with_path("verify-code").post(verification::verify_code))
        .push(Router::with_path("reset-email-or-phone").post(verification::reset_email_or_phone))
        .push(
            Router::with_path("entries")
                .get(verification::list_verifications)
                .push(Router::with_path("{id}").get(verification::get_verification)),
        )
}

fn webhook_routes() -> Router {
    Router::with_path("webhooks")
        .get(webhook::list_webhooks)
        .post(webhook::create_webhook)
        .push(
            Router::with_path("{id}")
                .get(webhook::get_webhook)
                .put(webhook::update_webhook)
                .delete(webhook::delete_webhook),
        )
}

fn syncer_routes() -> Router {
    Router::with_path("syncers")
        .get(syncer::list_syncers)
        .post(syncer::create_syncer)
        .push(Router::with_path("{id}/run").post(syncer::run_syncer))
        .push(
            Router::with_path("{id}")
                .get(syncer::get_syncer)
                .put(syncer::update_syncer)
                .delete(syncer::delete_syncer),
        )
}

fn invitation_routes() -> Router {
    Router::with_path("invitations")
        .get(invitation::list_invitations)
        .post(invitation::create_invitation)
        .push(Router::with_path("verify").post(invitation::verify_invitation))
        .push(Router::with_path("send").post(invitation::send_invitation))
        .push(
            Router::with_path("{id}")
                .get(invitation::get_invitation)
                .put(invitation::update_invitation)
                .delete(invitation::delete_invitation),
        )
}

fn mfa_routes() -> Router {
    Router::with_path("mfa")
        .push(Router::with_path("setup/initiate").post(mfa::initiate_mfa_setup))
        .push(Router::with_path("setup/verify").post(mfa::verify_mfa_setup))
        .push(Router::with_path("setup/enable").post(mfa::enable_mfa))
        .push(Router::with_path("delete").post(mfa::delete_mfa))
        .push(Router::with_path("set-preferred").post(mfa::set_preferred_mfa))
}

fn record_routes() -> Router {
    Router::with_path("records")
        .get(record::list_records)
        .post(record::create_record)
        .push(Router::with_path("filter").post(record::filter_records))
        .push(
            Router::with_path("{id}")
                .get(record::get_record)
                .put(record::update_record)
                .delete(record::delete_record),
        )
}

fn saml_routes() -> Router {
    Router::with_path("saml")
        .push(Router::with_path("metadata").get(saml::saml_metadata))
        .push(Router::with_path("login").get(saml::get_saml_login))
        .push(
            Router::with_path("acs")
                .post(saml::saml_acs)
                .get(saml::saml_acs),
        )
}

fn cas_routes() -> Router {
    Router::with_path("cas")
        .push(Router::with_path("serviceValidate").get(cas::service_validate))
        .push(Router::with_path("validate").get(cas::validate))
}

fn scim_routes() -> Router {
    Router::with_path("scim/v2")
        .push(Router::with_path("Users").get(scim::list_scim_users))
        .push(Router::with_path("Users/{id}").get(scim::get_scim_user))
}

fn ldap_routes() -> Router {
    Router::with_path("ldap")
        .get(ldap::get_ldaps)
        .post(ldap::add_ldap)
        .push(Router::with_path("{id}").get(ldap::get_ldap_provider_public))
        .push(Router::with_path("sync-users").post(ldap::sync_ldap_users))
        .push(Router::with_path("users").get(ldap::get_ldap_users))
        .push(Router::with_path("test-connection").post(ldap::test_ldap_connection))
}

fn model_routes() -> Router {
    Router::with_path("models")
        .get(model::list_models)
        .post(model::create_model)
        .push(
            Router::with_path("{id}")
                .get(model::get_model)
                .put(model::update_model)
                .delete(model::delete_model),
        )
}

fn adapter_routes() -> Router {
    Router::with_path("adapters")
        .get(adapter::list_adapters)
        .post(adapter::create_adapter)
        .push(
            Router::with_path("{id}")
                .get(adapter::get_adapter)
                .put(adapter::update_adapter)
                .delete(adapter::delete_adapter),
        )
}

fn enforcer_routes() -> Router {
    Router::with_path("enforcers")
        .get(enforcer::list_enforcers)
        .post(enforcer::create_enforcer)
        .push(
            Router::with_path("{id}")
                .get(enforcer::get_enforcer)
                .put(enforcer::update_enforcer)
                .delete(enforcer::delete_enforcer),
        )
}

fn rule_routes() -> Router {
    Router::with_path("rules")
        .get(rule::list_rules)
        .post(rule::create_rule)
        .push(
            Router::with_path("{id}")
                .get(rule::get_rule)
                .put(rule::update_rule)
                .delete(rule::delete_rule),
        )
}

fn site_routes() -> Router {
    Router::with_path("sites")
        .get(site::list_sites)
        .post(site::create_site)
        .push(
            Router::with_path("{id}")
                .get(site::get_site)
                .put(site::update_site)
                .delete(site::delete_site),
        )
}

fn product_routes() -> Router {
    Router::with_path("products")
        .get(product::list_products)
        .post(product::create_product)
        .push(
            Router::with_path("{id}")
                .get(product::get_product)
                .put(product::update_product)
                .delete(product::delete_product),
        )
}

fn plan_routes() -> Router {
    Router::with_path("plans")
        .get(plan::list_plans)
        .post(plan::create_plan)
        .push(
            Router::with_path("{id}")
                .get(plan::get_plan)
                .put(plan::update_plan)
                .delete(plan::delete_plan),
        )
}

fn pricing_routes() -> Router {
    Router::with_path("pricings")
        .get(pricing::list_pricings)
        .post(pricing::create_pricing)
        .push(
            Router::with_path("{id}")
                .get(pricing::get_pricing)
                .put(pricing::update_pricing)
                .delete(pricing::delete_pricing),
        )
}

fn subscription_routes() -> Router {
    Router::with_path("subscriptions")
        .get(subscription::list_subscriptions)
        .post(subscription::create_subscription)
        .push(
            Router::with_path("{id}")
                .get(subscription::get_subscription)
                .put(subscription::update_subscription)
                .delete(subscription::delete_subscription),
        )
}

fn payment_routes() -> Router {
    Router::with_path("payments")
        .get(payment::list_payments)
        .post(payment::create_payment)
        .push(Router::with_path("notify").post(payment::notify_payment))
        .push(Router::with_path("invoice").post(payment::invoice_payment))
        .push(
            Router::with_path("{id}")
                .get(payment::get_payment)
                .put(payment::update_payment)
                .delete(payment::delete_payment),
        )
}

fn transaction_routes() -> Router {
    Router::with_path("transactions")
        .get(transaction::list_transactions)
        .post(transaction::create_transaction)
        .push(
            Router::with_path("{id}")
                .get(transaction::get_transaction)
                .put(transaction::update_transaction)
                .delete(transaction::delete_transaction),
        )
}

fn order_routes() -> Router {
    Router::with_path("orders")
        .get(order::get_orders)
        .post(order::add_order)
        .push(Router::with_path("{id}/pay").post(order::pay_order))
        .push(Router::with_path("{id}/cancel").post(order::cancel_order))
        .push(
            Router::with_path("{id}")
                .get(order::get_order)
                .put(order::update_order)
                .delete(order::delete_order),
        )
}

fn ticket_routes() -> Router {
    Router::with_path("tickets")
        .get(ticket::get_tickets)
        .post(ticket::add_ticket)
        .push(
            Router::with_path("{id}")
                .get(ticket::get_ticket)
                .put(ticket::update_ticket)
                .delete(ticket::delete_ticket),
        )
}

fn form_routes() -> Router {
    Router::with_path("forms")
        .get(form::get_forms)
        .post(form::add_form)
        .push(
            Router::with_path("{id}")
                .get(form::get_form)
                .put(form::update_form)
                .delete(form::delete_form),
        )
}

fn swagger_router() -> Router {
    let doc = create_openapi_doc();
    Router::new()
        .push(doc.into_router("/api-doc/openapi.json"))
        .push(Router::with_path("swagger-ui/{**}").get(SwaggerUi::new("/api-doc/openapi.json")))
}

pub fn create_openapi_doc() -> OpenApi {
    OpenApi::new("Casdog API", env!("CARGO_PKG_VERSION"))
        .add_server(salvo::oapi::Server::new("/"))
        .merge_router(&api_router_for_openapi())
}

fn api_router_for_openapi() -> Router {
    Router::with_path("api").push(
        Router::new()
            .push(Router::with_path("health").get(health::health_check))
            .push(Router::with_path("signup").post(auth::signup))
            .push(Router::with_path("login").post(auth::login))
            .push(Router::with_path("get-app-login").get(auth::get_app_login))
            .push(Router::with_path("logout").get(auth::logout).post(auth::logout))
            .push(Router::with_path("get-account").get(auth::get_account))
            .push(Router::with_path("set-password").post(auth::set_password))
            .push(Router::with_path("check-user-password").post(auth::check_user_password))
            .push(Router::with_path("reset-email-or-phone").post(verification::reset_email_or_phone))
            .push(Router::with_path("grant-consent").post(consent::grant_consent))
            .push(Router::with_path("revoke-consent").post(consent::revoke_consent))
            .push(Router::with_path("sso-logout").get(auth::sso_logout).post(auth::sso_logout))
            .push(Router::with_path("unlink").post(social_login::unlink_provider_compat))
            .push(
                Router::with_path("mfa")
                    .push(Router::with_path("setup/initiate").post(mfa::initiate_mfa_setup))
                    .push(Router::with_path("setup/verify").post(mfa::verify_mfa_setup))
                    .push(Router::with_path("setup/enable").post(mfa::enable_mfa))
                    .push(Router::with_path("delete").post(mfa::delete_mfa))
                    .push(Router::with_path("set-preferred").post(mfa::set_preferred_mfa)),
            )
            .push(Router::with_path("userinfo").get(oidc::userinfo))
            .push(Router::with_path("captcha").get(verification::get_captcha))
            .push(Router::with_path("get-captcha-status").get(auth::get_captcha_status))
            .push(Router::with_path("verify-captcha").post(verification::verify_captcha))
            .push(Router::with_path("get-email-and-phone").post(verification::get_email_and_phone))
            .push(Router::with_path("callback").get(auth::callback).post(auth::callback))
            .push(Router::with_path("device-auth").post(auth::device_auth))
            .push(Router::with_path("kerberos-login").get(login_compat::kerberos_login))
            .push(Router::with_path("oauth/register").post(auth::oauth_register))
            .push(Router::with_path("get-qrcode").get(auth::get_qrcode))
            .push(Router::with_path("get-webhook-event").get(auth::get_webhook_event))
            .push(Router::with_path("faceid-signin-begin").get(login_compat::faceid_signin_begin))
            .push(Router::with_path("faceid-signin-finish").post(login_compat::faceid_signin_finish))
            .push(
                Router::with_path("saml")
                    .push(Router::with_path("metadata").get(saml::saml_metadata))
                    .push(Router::with_path("login").get(saml::get_saml_login))
                    .push(Router::with_path("acs").post(saml::saml_acs).get(saml::saml_acs))
                    .push(
                        Router::with_path("redirect/{owner}/{application}")
                            .get(saml::saml_redirect),
                    ),
            )
            .push(Router::with_path("get-saml-login").get(saml::get_saml_login))
            .push(Router::with_path("acs").post(saml::saml_acs).get(saml::saml_acs))
            .push(Router::with_path("webauthn/signup/begin").get(webauthn::signup_begin))
            .push(Router::with_path("webauthn/signup/finish").post(webauthn::signup_finish))
            .push(Router::with_path("webauthn/signin/begin").get(webauthn::signin_begin))
            .push(Router::with_path("webauthn/signin/finish").post(webauthn::signin_finish))
            .push(Router::with_path("webauthn/credentials").get(webauthn::list_credentials))
            .push(
                Router::with_path("webauthn/credentials/{id}")
                    .delete(webauthn::delete_credential),
            )
            // Social login endpoints
            .push(Router::with_path("auth/{provider}").get(social_login::get_provider_auth_url))
            .push(Router::with_path("auth/{provider}/callback").get(social_login::provider_callback))
            .push(Router::with_path("unlink").post(social_login::unlink_provider_compat))
            .push(Router::with_path("auth/{provider}/unlink").post(social_login::unlink_provider))
            // OAuth endpoints
            .push(
                Router::with_path("login/oauth")
                    .push(Router::with_path("access_token").post(auth::oauth_access_token))
                    .push(Router::with_path("refresh_token").post(auth::oauth_refresh_token))
                    .push(Router::with_path("introspect").post(auth::oauth_introspect))
                    .push(Router::with_path("revoke").post(auth::oauth_revoke)),
            )
            .push(
                Router::with_path("users")
                    .get(user::list_users)
                    .post(user::create_user)
                    .push(
                        Router::with_path("{id}")
                            .get(user::get_user)
                            .put(user::update_user)
                            .delete(user::delete_user),
                    ),
            )
            .push(
                Router::with_path("organizations")
                    .get(organization::list_organizations)
                    .post(organization::create_organization)
                    .push(
                        Router::with_path("{id}")
                            .get(organization::get_organization)
                            .put(organization::update_organization)
                            .delete(organization::delete_organization),
                    ),
            )
            .push(
                Router::with_path("applications")
                    .get(application::list_applications)
                    .post(application::create_application)
                    .push(
                        Router::with_path("{id}")
                            .get(application::get_application)
                            .put(application::update_application)
                            .delete(application::delete_application),
                    ),
            )
            .push(
                Router::with_path("roles")
                    .get(role::list_roles)
                    .post(role::create_role)
                    .push(Router::with_path("assign").post(role::assign_role))
                    .push(Router::with_path("user/{user_id}").get(role::get_user_roles))
                    .push(
                        Router::with_path("{id}")
                            .get(role::get_role)
                            .put(role::update_role)
                            .delete(role::delete_role),
                    ),
            )
            .push(
                Router::with_path("permissions")
                    .get(permission::list_permissions)
                    .post(permission::create_permission)
                    .push(Router::with_path("assign").post(permission::assign_permission))
                    .push(
                        Router::with_path("role/{role_id}").get(permission::get_role_permissions),
                    )
                    .push(
                        Router::with_path("{id}")
                            .get(permission::get_permission)
                            .put(permission::update_permission)
                            .delete(permission::delete_permission),
                    ),
            )
            .push(Router::with_path("enforce").post(policy::enforce))
            .push(Router::with_path("batch-enforce").post(policy::batch_enforce))
            .push(Router::with_path("get-all-objects").get(policy::get_all_objects))
            .push(Router::with_path("get-all-actions").get(policy::get_all_actions))
            .push(Router::with_path("get-all-roles").get(policy::get_all_roles))
            .push(
                Router::with_path("policies")
                    .get(policy::get_policies)
                    .post(policy::add_policy)
                    .delete(policy::remove_policy),
            )
            .push(
                Router::with_path("providers")
                    .get(provider::list_providers)
                    .post(provider::create_provider)
                    .push(
                        Router::with_path("{id}")
                            .get(provider::get_provider)
                            .put(provider::update_provider)
                            .delete(provider::delete_provider),
                    ),
            )
            .push(
                Router::with_path("tokens")
                    .get(token::list_tokens)
                    .post(token::create_token)
                    .push(
                        Router::with_path("{id}")
                            .get(token::get_token)
                            .put(token::update_token)
                            .delete(token::delete_token),
                    ),
            )
            .push(
                Router::with_path("groups")
                    .get(group::list_groups)
                    .post(group::create_group)
                    .push(Router::with_path("add-user").post(group::add_user_to_group))
                    .push(Router::with_path("remove-user").post(group::remove_user_from_group))
                    .push(
                        Router::with_path("{id}")
                            .get(group::get_group)
                            .put(group::update_group)
                            .delete(group::delete_group),
                    )
                    .push(Router::with_path("{id}/users").get(group::get_users_in_group)),
            )
            .push(
                Router::with_path("sessions")
                    .get(session::list_sessions)
                    .post(session::create_session)
                    .push(Router::with_path("is-duplicated").post(session::is_session_duplicated))
                    .push(
                        Router::with_path("{id}")
                            .get(session::get_session)
                            .put(session::update_session)
                            .delete(session::delete_session),
                    ),
            )
            .push(
                Router::with_path("certs")
                    .get(cert::list_certs)
                    .post(cert::create_cert)
                    .push(
                        Router::with_path("{id}")
                            .get(cert::get_cert)
                            .put(cert::update_cert)
                            .delete(cert::delete_cert),
                    ),
            )
            .push(
                Router::with_path("resources")
                    .get(resource::list_resources)
                    .post(resource::create_resource)
                    .push(
                        Router::with_path("{id}")
                            .get(resource::get_resource)
                            .put(resource::update_resource)
                            .delete(resource::delete_resource),
                    ),
            )
            .push(
                Router::with_path("verification")
                    .push(Router::with_path("send-code").post(verification::send_verification_code))
                    .push(Router::with_path("verify-code").post(verification::verify_code))
                    .push(Router::with_path("reset-email-or-phone").post(verification::reset_email_or_phone))
                    .push(
                        Router::with_path("entries")
                            .get(verification::list_verifications)
                            .push(Router::with_path("{id}").get(verification::get_verification)),
                    ),
            )
            .push(
                Router::with_path("webhooks")
                    .get(webhook::list_webhooks)
                    .post(webhook::create_webhook)
                    .push(
                        Router::with_path("{id}")
                            .get(webhook::get_webhook)
                            .put(webhook::update_webhook)
                            .delete(webhook::delete_webhook),
                    ),
            )
            .push(
                Router::with_path("syncers")
                    .get(syncer::list_syncers)
                    .post(syncer::create_syncer)
                    .push(Router::with_path("{id}/run").post(syncer::run_syncer))
                    .push(
                        Router::with_path("{id}")
                            .get(syncer::get_syncer)
                            .put(syncer::update_syncer)
                            .delete(syncer::delete_syncer),
                    ),
            )
            .push(
                Router::with_path("invitations")
                    .get(invitation::list_invitations)
                    .post(invitation::create_invitation)
                    .push(Router::with_path("verify").post(invitation::verify_invitation))
                    .push(Router::with_path("send").post(invitation::send_invitation))
                    .push(
                        Router::with_path("{id}")
                            .get(invitation::get_invitation)
                            .put(invitation::update_invitation)
                            .delete(invitation::delete_invitation),
                    ),
            )
            .push(
                Router::with_path("records")
                    .get(record::list_records)
                    .post(record::create_record)
                    .push(Router::with_path("filter").post(record::filter_records))
                    .push(
                        Router::with_path("{id}")
                            .get(record::get_record)
                            .put(record::update_record)
                            .delete(record::delete_record),
                    ),
            )
            .push(
                Router::with_path("models")
                    .get(model::list_models)
                    .post(model::create_model)
                    .push(
                        Router::with_path("{id}")
                            .get(model::get_model)
                            .put(model::update_model)
                            .delete(model::delete_model),
                    ),
            )
            .push(
                Router::with_path("adapters")
                    .get(adapter::list_adapters)
                    .post(adapter::create_adapter)
                    .push(
                        Router::with_path("{id}")
                            .get(adapter::get_adapter)
                            .put(adapter::update_adapter)
                            .delete(adapter::delete_adapter),
                    ),
            )
            .push(
                Router::with_path("enforcers")
                    .get(enforcer::list_enforcers)
                    .post(enforcer::create_enforcer)
                    .push(
                        Router::with_path("{id}")
                            .get(enforcer::get_enforcer)
                            .put(enforcer::update_enforcer)
                            .delete(enforcer::delete_enforcer),
                    ),
            )
            .push(
                Router::with_path("rules")
                    .get(rule::list_rules)
                    .post(rule::create_rule)
                    .push(
                        Router::with_path("{id}")
                            .get(rule::get_rule)
                            .put(rule::update_rule)
                            .delete(rule::delete_rule),
                    ),
            )
            .push(
                Router::with_path("sites")
                    .get(site::list_sites)
                    .post(site::create_site)
                    .push(
                        Router::with_path("{id}")
                            .get(site::get_site)
                            .put(site::update_site)
                            .delete(site::delete_site),
                    ),
            )
            // Phase 8: Extra convenience query endpoints
            .push(Router::with_path("get-global-users").get(user_extra::get_global_users))
            .push(Router::with_path("get-sorted-users").get(user_extra::get_sorted_users))
            .push(Router::with_path("get-user-count").get(user_extra::get_user_count))
            .push(Router::with_path("get-organization-names").get(org_extra::get_organization_names))
            .push(Router::with_path("get-user-application").get(app_extra::get_user_application))
            .push(Router::with_path("get-organization-applications").get(app_extra::get_organization_applications))
            .push(Router::with_path("get-default-application").get(app_extra::get_default_application))
            .push(Router::with_path("get-global-providers").get(provider_extra::get_global_providers))
            .push(Router::with_path("get-global-certs").get(cert_extra::get_global_certs))
            .push(Router::with_path("get-global-rules").get(rule::get_global_rules))
            .push(Router::with_path("get-global-sites").get(site::get_global_sites))
            .push(Router::with_path("get-permissions-by-submitter").get(permission_extra::get_permissions_by_submitter))
            .push(Router::with_path("get-permissions-by-role").get(permission_extra::get_permissions_by_role))
            .push(Router::with_path("get-dashboard").get(dashboard::get_dashboard))
            .push(Router::with_path("metrics").get(dashboard::get_metrics))
            .push(Router::with_path("send-email").post(messaging::send_email))
            .push(Router::with_path("send-sms").post(messaging::send_sms))
            .push(Router::with_path("send-notification").post(messaging::send_notification))
            .push(Router::with_path("run-casbin-command").get(casbin_cli::run_casbin_command))
            .push(Router::with_path("refresh-engines").post(casbin_cli::refresh_engines))
            .push(Router::with_path("get-verifications").get(verification::list_verifications))
            .push(Router::with_path("get-verification").get(verification::get_verification_by_query))
            .push(Router::with_path("get-ldaps").get(ldap::get_ldaps))
            .push(Router::with_path("get-ldap").get(ldap::get_ldap))
            .push(Router::with_path("add-ldap").post(ldap::add_ldap))
            .push(Router::with_path("update-ldap").post(ldap::update_ldap))
            .push(Router::with_path("delete-ldap").post(ldap::delete_ldap))
            .push(Router::with_path("get-ldap-users").get(ldap::get_ldap_users))
            .push(Router::with_path("sync-ldap-users").post(ldap::sync_ldap_users))
            .push(Router::with_path("notify-payment").post(payment::notify_payment))
            .push(
                Router::with_path("notify-payment/{owner}/{payment}").post(payment::notify_payment),
            )
            .push(Router::with_path("invoice-payment").post(payment::invoice_payment))
            .push(Router::with_path("pay-order").post(order::pay_order))
            .push(Router::with_path("cancel-order").post(order::cancel_order))
            .push(Router::with_path("get-system-info").get(system::get_system_info))
            .push(Router::with_path("get-version-info").get(system::get_version_info))
            .push(Router::with_path("get-prometheus-info").get(system::get_prometheus_info))
            .push(Router::with_path("impersonate-user").post(impersonation::impersonate_user))
            .push(Router::with_path("exit-impersonate-user").post(impersonation::exit_impersonate_user))
            .push(
                Router::with_path("products")
                    .get(product::list_products)
                    .post(product::create_product)
                    .push(
                        Router::with_path("{id}")
                            .get(product::get_product)
                            .put(product::update_product)
                            .delete(product::delete_product),
                    ),
            )
            .push(
                Router::with_path("plans")
                    .get(plan::list_plans)
                    .post(plan::create_plan)
                    .push(
                        Router::with_path("{id}")
                            .get(plan::get_plan)
                            .put(plan::update_plan)
                            .delete(plan::delete_plan),
                    ),
            )
            .push(
                Router::with_path("pricings")
                    .get(pricing::list_pricings)
                    .post(pricing::create_pricing)
                    .push(
                        Router::with_path("{id}")
                            .get(pricing::get_pricing)
                            .put(pricing::update_pricing)
                            .delete(pricing::delete_pricing),
                    ),
            )
            .push(
                Router::with_path("subscriptions")
                    .get(subscription::list_subscriptions)
                    .post(subscription::create_subscription)
                    .push(
                        Router::with_path("{id}")
                            .get(subscription::get_subscription)
                            .put(subscription::update_subscription)
                            .delete(subscription::delete_subscription),
                    ),
            )
            .push(
                Router::with_path("payments")
                    .get(payment::list_payments)
                    .post(payment::create_payment)
                    .push(Router::with_path("notify").post(payment::notify_payment))
                    .push(Router::with_path("invoice").post(payment::invoice_payment))
                    .push(
                        Router::with_path("{id}")
                            .get(payment::get_payment)
                            .put(payment::update_payment)
                            .delete(payment::delete_payment),
                    ),
            )
            .push(
                Router::with_path("transactions")
                    .get(transaction::list_transactions)
                    .post(transaction::create_transaction)
                    .push(
                        Router::with_path("{id}")
                            .get(transaction::get_transaction)
                            .put(transaction::update_transaction)
                            .delete(transaction::delete_transaction),
                    ),
            )
            .push(
                Router::with_path("orders")
                    .get(order::get_orders)
                    .post(order::add_order)
                    .push(Router::with_path("{id}/pay").post(order::pay_order))
                    .push(Router::with_path("{id}/cancel").post(order::cancel_order))
                    .push(
                        Router::with_path("{id}")
                            .get(order::get_order)
                            .put(order::update_order)
                            .delete(order::delete_order),
                    ),
            )
            .push(
                Router::with_path("tickets")
                    .get(ticket::get_tickets)
                    .post(ticket::add_ticket)
                    .push(
                        Router::with_path("{id}")
                            .get(ticket::get_ticket)
                            .put(ticket::update_ticket)
                            .delete(ticket::delete_ticket),
                    ),
            )
            .push(
                Router::with_path("forms")
                    .get(form::get_forms)
                    .post(form::add_form)
                    .push(
                        Router::with_path("{id}")
                            .get(form::get_form)
                            .put(form::update_form)
                            .delete(form::delete_form),
                    ),
            )
            .push(Router::with_path("upload-users").post(upload::upload_users))
            .push(Router::with_path("upload-groups").post(upload::upload_groups))
            .push(Router::with_path("upload-roles").post(upload::upload_roles))
            .push(Router::with_path("upload-permissions").post(upload::upload_permissions))
            // File upload/download/delete with storage provider integration
            .push(Router::with_path("upload-resource").post(upload::upload_resource))
            .push(Router::with_path("download-resource/{id}").get(upload::download_resource))
            .push(Router::with_path("delete-resource/{id}").post(upload::delete_resource_with_file)),
    )
}

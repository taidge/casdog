use crate::handlers::{
    adapter, app_extra, application, auth, cas, cert, cert_extra, dashboard, enforcer, group,
    health, impersonation, invitation, ldap, messaging, mfa, model, oidc, org_extra, organization,
    payment, permission, permission_extra, plan, policy, pricing, product, provider, provider_extra,
    record, resource, role, saml, scim, session, subscription, syncer, system, token, transaction,
    user, user_extra, verification, webhook,
};
use crate::middleware::JwtAuth;
use rust_embed::Embed;
use salvo::oapi::OpenApi;
use salvo::prelude::*;
use salvo::serve_static::static_embed;

#[derive(Embed)]
#[folder = "../../web/dist"]
struct Assets;

pub fn create_router() -> Router {
    Router::new()
        .push(wellknown_router())
        .push(api_router())
        .push(oauth_router())
        .push(swagger_router())
        .push(static_router())
}

fn static_router() -> Router {
    Router::new()
        .push(Router::with_path("<**path>").get(static_embed::<Assets>().fallback("index.html")))
}

fn wellknown_router() -> Router {
    Router::with_path(".well-known")
        .push(Router::with_path("openid-configuration").get(oidc::openid_configuration))
        .push(Router::with_path("jwks").get(oidc::jwks))
        .push(Router::with_path("webfinger").get(oidc::webfinger))
        .push(Router::with_path("<application>/openid-configuration").get(oidc::app_openid_configuration))
        .push(Router::with_path("<application>/jwks").get(oidc::app_jwks))
}

fn oauth_router() -> Router {
    Router::with_path("login/oauth")
        .push(Router::with_path("authorize").get(oidc::authorize))
        .push(Router::with_path("access_token").post(auth::oauth_access_token))
        .push(Router::with_path("refresh_token").post(auth::oauth_refresh_token))
        .push(Router::with_path("introspect").post(auth::oauth_introspect))
        .push(Router::with_path("revoke").post(auth::oauth_revoke))
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
        .push(Router::with_path("userinfo").get(oidc::userinfo))
        .push(Router::with_path("captcha").get(verification::get_captcha))
        .push(Router::with_path("verify-captcha").post(verification::verify_captcha))
        .push(Router::with_path("get-email-and-phone").post(verification::get_email_and_phone))
}

fn protected_routes() -> Router {
    Router::new()
        .hoop(JwtAuth)
        .push(Router::with_path("logout").post(auth::logout))
        .push(Router::with_path("get-account").get(auth::get_account))
        .push(Router::with_path("set-password").post(auth::set_password))
        .push(Router::with_path("check-user-password").post(auth::check_user_password))
        .push(Router::with_path("sso-logout").post(auth::sso_logout))
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
        .push(saml_routes())
        .push(cas_routes())
        .push(scim_routes())
        .push(ldap_routes())
        .push(model_routes())
        .push(adapter_routes())
        .push(enforcer_routes())
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
        .push(Router::with_path("get-permissions-by-submitter").get(permission_extra::get_permissions_by_submitter))
        .push(Router::with_path("get-permissions-by-role").get(permission_extra::get_permissions_by_role))
        .push(Router::with_path("get-dashboard").get(dashboard::get_dashboard))
        .push(Router::with_path("metrics").get(dashboard::get_metrics))
        .push(Router::with_path("send-email").post(messaging::send_email))
        .push(Router::with_path("send-sms").post(messaging::send_sms))
        .push(Router::with_path("send-notification").post(messaging::send_notification))
        // System info
        .push(Router::with_path("get-system-info").get(system::get_system_info))
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
}

fn user_routes() -> Router {
    Router::with_path("users")
        .get(user::list_users)
        .post(user::create_user)
        .push(
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
        .push(Router::with_path("user/<user_id>").get(role::get_user_roles))
        .push(
            Router::with_path("<id>")
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
        .push(Router::with_path("role/<role_id>").get(permission::get_role_permissions))
        .push(
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
            Router::with_path("<id>")
                .get(group::get_group)
                .put(group::update_group)
                .delete(group::delete_group),
        )
        .push(Router::with_path("<id>/users").get(group::get_users_in_group))
}

fn session_routes() -> Router {
    Router::with_path("sessions")
        .get(session::list_sessions)
        .post(session::create_session)
        .push(Router::with_path("is-duplicated").post(session::is_session_duplicated))
        .push(
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
            Router::with_path("<id>")
                .get(resource::get_resource)
                .put(resource::update_resource)
                .delete(resource::delete_resource),
        )
}

fn verification_routes() -> Router {
    Router::with_path("verification")
        .push(Router::with_path("send-code").post(verification::send_verification_code))
        .push(Router::with_path("verify-code").post(verification::verify_code))
}

fn webhook_routes() -> Router {
    Router::with_path("webhooks")
        .get(webhook::list_webhooks)
        .post(webhook::create_webhook)
        .push(
            Router::with_path("<id>")
                .get(webhook::get_webhook)
                .put(webhook::update_webhook)
                .delete(webhook::delete_webhook),
        )
}

fn syncer_routes() -> Router {
    Router::with_path("syncers")
        .get(syncer::list_syncers)
        .post(syncer::create_syncer)
        .push(Router::with_path("<id>/run").post(syncer::run_syncer))
        .push(
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
        .push(Router::with_path("filter").post(record::filter_records))
        .push(
            Router::with_path("<id>")
                .get(record::get_record)
                .delete(record::delete_record),
        )
}

fn saml_routes() -> Router {
    Router::with_path("saml")
        .push(Router::with_path("metadata").get(saml::saml_metadata))
        .push(Router::with_path("login").get(saml::get_saml_login))
        .push(Router::with_path("acs").post(saml::saml_acs))
}

fn cas_routes() -> Router {
    Router::with_path("cas")
        .push(Router::with_path("serviceValidate").get(cas::service_validate))
        .push(Router::with_path("validate").get(cas::validate))
}

fn scim_routes() -> Router {
    Router::with_path("scim/v2")
        .push(Router::with_path("Users").get(scim::list_scim_users))
        .push(Router::with_path("Users/<id>").get(scim::get_scim_user))
}

fn ldap_routes() -> Router {
    Router::with_path("ldap")
        .push(Router::with_path("sync-users").post(ldap::sync_ldap_users))
        .push(Router::with_path("test-connection").post(ldap::test_ldap_connection))
}

fn model_routes() -> Router {
    Router::with_path("models")
        .get(model::list_models)
        .post(model::create_model)
        .push(
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
            Router::with_path("<id>")
                .get(enforcer::get_enforcer)
                .put(enforcer::update_enforcer)
                .delete(enforcer::delete_enforcer),
        )
}

fn product_routes() -> Router {
    Router::with_path("products")
        .get(product::list_products)
        .post(product::create_product)
        .push(
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
            Router::with_path("<id>")
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
            Router::with_path("<id>")
                .get(subscription::get_subscription)
                .put(subscription::update_subscription)
                .delete(subscription::delete_subscription),
        )
}

fn payment_routes() -> Router {
    Router::with_path("payments")
        .get(payment::list_payments)
        .post(payment::create_payment)
        .push(
            Router::with_path("<id>")
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
            Router::with_path("<id>")
                .get(transaction::get_transaction)
                .put(transaction::update_transaction)
                .delete(transaction::delete_transaction),
        )
}

fn swagger_router() -> Router {
    let doc = create_openapi_doc();
    Router::new()
        .push(doc.into_router("/api-doc/openapi.json"))
        .push(
            Router::with_path("swagger-ui/<**>")
                .get(SwaggerUi::new("/api-doc/openapi.json")),
        )
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
            .push(Router::with_path("logout").post(auth::logout))
            .push(Router::with_path("get-account").get(auth::get_account))
            .push(Router::with_path("set-password").post(auth::set_password))
            .push(Router::with_path("check-user-password").post(auth::check_user_password))
            .push(Router::with_path("sso-logout").post(auth::sso_logout))
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
            .push(Router::with_path("verify-captcha").post(verification::verify_captcha))
            .push(Router::with_path("get-email-and-phone").post(verification::get_email_and_phone))
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
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
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
                    .push(Router::with_path("user/<user_id>").get(role::get_user_roles))
                    .push(
                        Router::with_path("<id>")
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
                        Router::with_path("role/<role_id>").get(permission::get_role_permissions),
                    )
                    .push(
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
                            .get(group::get_group)
                            .put(group::update_group)
                            .delete(group::delete_group),
                    )
                    .push(Router::with_path("<id>/users").get(group::get_users_in_group)),
            )
            .push(
                Router::with_path("sessions")
                    .get(session::list_sessions)
                    .post(session::create_session)
                    .push(Router::with_path("is-duplicated").post(session::is_session_duplicated))
                    .push(
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
                            .get(resource::get_resource)
                            .put(resource::update_resource)
                            .delete(resource::delete_resource),
                    ),
            )
            .push(
                Router::with_path("verification")
                    .push(Router::with_path("send-code").post(verification::send_verification_code))
                    .push(Router::with_path("verify-code").post(verification::verify_code)),
            )
            .push(
                Router::with_path("webhooks")
                    .get(webhook::list_webhooks)
                    .post(webhook::create_webhook)
                    .push(
                        Router::with_path("<id>")
                            .get(webhook::get_webhook)
                            .put(webhook::update_webhook)
                            .delete(webhook::delete_webhook),
                    ),
            )
            .push(
                Router::with_path("syncers")
                    .get(syncer::list_syncers)
                    .post(syncer::create_syncer)
                    .push(Router::with_path("<id>/run").post(syncer::run_syncer))
                    .push(
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
                            .get(invitation::get_invitation)
                            .put(invitation::update_invitation)
                            .delete(invitation::delete_invitation),
                    ),
            )
            .push(
                Router::with_path("records")
                    .get(record::list_records)
                    .push(Router::with_path("filter").post(record::filter_records))
                    .push(
                        Router::with_path("<id>")
                            .get(record::get_record)
                            .delete(record::delete_record),
                    ),
            )
            .push(
                Router::with_path("models")
                    .get(model::list_models)
                    .post(model::create_model)
                    .push(
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
                            .get(enforcer::get_enforcer)
                            .put(enforcer::update_enforcer)
                            .delete(enforcer::delete_enforcer),
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
            .push(Router::with_path("get-permissions-by-submitter").get(permission_extra::get_permissions_by_submitter))
            .push(Router::with_path("get-permissions-by-role").get(permission_extra::get_permissions_by_role))
            .push(Router::with_path("get-dashboard").get(dashboard::get_dashboard))
            .push(Router::with_path("metrics").get(dashboard::get_metrics))
            .push(Router::with_path("send-email").post(messaging::send_email))
            .push(Router::with_path("send-sms").post(messaging::send_sms))
            .push(Router::with_path("send-notification").post(messaging::send_notification))
            .push(Router::with_path("get-system-info").get(system::get_system_info))
            .push(Router::with_path("get-prometheus-info").get(system::get_prometheus_info))
            .push(Router::with_path("impersonate-user").post(impersonation::impersonate_user))
            .push(Router::with_path("exit-impersonate-user").post(impersonation::exit_impersonate_user))
            .push(
                Router::with_path("products")
                    .get(product::list_products)
                    .post(product::create_product)
                    .push(
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
                            .get(subscription::get_subscription)
                            .put(subscription::update_subscription)
                            .delete(subscription::delete_subscription),
                    ),
            )
            .push(
                Router::with_path("payments")
                    .get(payment::list_payments)
                    .post(payment::create_payment)
                    .push(
                        Router::with_path("<id>")
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
                        Router::with_path("<id>")
                            .get(transaction::get_transaction)
                            .put(transaction::update_transaction)
                            .delete(transaction::delete_transaction),
                    ),
            ),
    )
}

// OAuth/OIDC Providers
pub mod oauth_provider;
pub mod github;
pub mod google;
pub mod generic_oauth;
pub mod facebook;
pub mod microsoft;
pub mod apple;
pub mod gitlab;
pub mod discord;
pub mod slack;
pub mod twitter;
pub mod linkedin;
pub mod bitbucket;
pub mod okta;
pub mod wechat;
pub mod dingtalk;
pub mod lark;
pub mod telegram;
pub mod steam;

// Notification Providers
pub mod notification_provider;
pub mod telegram_notify;
pub mod slack_notify;
pub mod discord_notify;
pub mod dingtalk_notify;
pub mod lark_notify;
pub mod teams_notify;
pub mod custom_http_notify;

// Email Providers
pub mod email_provider;
pub mod email_extra;

// SMS Providers
pub mod sms_provider;

// Captcha Providers
pub mod captcha_provider;

// Storage Providers
pub mod storage_provider;
pub mod local_storage;
pub mod s3_storage;

// Payment Providers
pub mod payment_provider;
pub mod stripe_payment;
pub mod paypal_payment;
pub mod balance_payment;
pub mod dummy_payment;

pub use oauth_provider::*;
pub use notification_provider::*;
pub use email_provider::*;
pub use email_extra::*;
pub use sms_provider::*;
pub use captcha_provider::*;
pub use storage_provider::*;
pub use payment_provider::*;

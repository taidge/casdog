// OAuth/OIDC Providers
pub mod apple;
pub mod bitbucket;
pub mod dingtalk;
pub mod discord;
pub mod facebook;
pub mod generic_oauth;
pub mod github;
pub mod gitlab;
pub mod google;
pub mod lark;
pub mod linkedin;
pub mod microsoft;
pub mod oauth_provider;
pub mod okta;
pub mod slack;
pub mod steam;
pub mod telegram;
pub mod twitter;
pub mod wechat;

// Notification Providers
pub mod custom_http_notify;
pub mod dingtalk_notify;
pub mod discord_notify;
pub mod lark_notify;
pub mod notification_provider;
pub mod slack_notify;
pub mod teams_notify;
pub mod telegram_notify;

// Email Providers
pub mod email_extra;
pub mod email_provider;

// SMS Providers
pub mod sms_provider;

// Captcha Providers
pub mod captcha_provider;

// Storage Providers
pub mod local_storage;
pub mod s3_storage;
pub mod storage_provider;

// Payment Providers
pub mod balance_payment;
pub mod dummy_payment;
pub mod payment_provider;
pub mod paypal_payment;
pub mod stripe_payment;

pub use captcha_provider::*;
pub use email_extra::*;
pub use email_provider::*;
pub use notification_provider::*;
pub use oauth_provider::*;
pub use payment_provider::*;
pub use sms_provider::*;
pub use storage_provider::*;

pub mod oauth_provider;
pub mod github;
pub mod google;
pub mod generic_oauth;
pub mod email_provider;
pub mod sms_provider;
pub mod captcha_provider;

pub use oauth_provider::*;
pub use email_provider::*;
pub use sms_provider::*;
pub use captcha_provider::*;

pub mod account;
pub mod authorize;
pub mod consent;
pub mod device_auth;
pub mod forgot_password;
pub mod login;
pub mod result;
pub mod signup;

pub use account::AccountPage;
pub use authorize::AuthorizePage;
pub use consent::ConsentPage;
pub use device_auth::DeviceAuthPage;
pub use forgot_password::ForgotPasswordPage;
pub use login::LoginPage;
pub use result::ResultPage;
pub use signup::SignupPage;

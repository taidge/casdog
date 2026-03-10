pub mod login;
pub mod signup;
pub mod authorize;
pub mod consent;
pub mod device_auth;
pub mod account;
pub mod result;
pub mod forgot_password;

pub use login::LoginPage;
pub use signup::SignupPage;
pub use authorize::AuthorizePage;
pub use consent::ConsentPage;
pub use device_auth::DeviceAuthPage;
pub use account::AccountPage;
pub use result::ResultPage;
pub use forgot_password::ForgotPasswordPage;

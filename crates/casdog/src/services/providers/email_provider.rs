use async_trait::async_trait;

use crate::error::{AppError, AppResult};

/// Trait for email sending providers
#[async_trait]
pub trait EmailProviderTrait: Send + Sync {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> AppResult<()>;
}

/// SMTP email provider using lettre
pub struct SmtpEmailProvider {
    host: String,
    port: u16,
    username: String,
    password: String,
    from_address: String,
    use_ssl: bool,
    ssl_mode: Option<String>,
}

impl SmtpEmailProvider {
    pub fn new(
        host: String,
        port: u16,
        username: String,
        password: String,
        from_address: String,
        use_ssl: bool,
    ) -> Self {
        Self {
            host,
            port,
            username,
            password,
            from_address,
            use_ssl,
            ssl_mode: None,
        }
    }

    /// An explicit mode follows upstream gomail; None/empty retains the safer
    /// pre-existing disable_ssl behavior for records which never opted in.
    pub fn with_ssl_mode(mut self, mode: Option<&str>) -> AppResult<Self> {
        smtp_tls_mode(mode, !self.use_ssl, self.port)?;
        self.ssl_mode = mode.map(str::to_owned);
        Ok(self)
    }

    pub fn from_provider_record(
        host: &str,
        port: i32,
        client_id: &str,
        client_secret: &str,
        from_address: &str,
        enable_ssl: bool,
    ) -> Self {
        Self::new(
            host.to_string(),
            port as u16,
            client_id.to_string(),
            client_secret.to_string(),
            from_address.to_string(),
            enable_ssl,
        )
    }
}

#[async_trait]
impl EmailProviderTrait for SmtpEmailProvider {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::transport::smtp::client::{Tls, TlsParameters};
        use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

        let email = Message::builder()
            .from(
                self.from_address
                    .parse()
                    .map_err(|e| AppError::Internal(format!("Invalid from address: {}", e)))?,
            )
            .to(to
                .parse()
                .map_err(|e| AppError::Internal(format!("Invalid to address: {}", e)))?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body.to_string())
            .map_err(|e| AppError::Internal(format!("Failed to build email: {}", e)))?;

        let creds = Credentials::new(self.username.clone(), self.password.clone());

        let mode = smtp_tls_mode(self.ssl_mode.as_deref(), !self.use_ssl, self.port)?;
        let parameters = TlsParameters::new(self.host.clone())
            .map_err(|_| AppError::Config("Invalid SMTP TLS configuration".into()))?;
        let tls = match mode {
            SmtpTlsMode::Implicit => Tls::Wrapper(parameters),
            SmtpTlsMode::RequiredStarttls => Tls::Required(parameters),
            SmtpTlsMode::OpportunisticStarttls => Tls::Opportunistic(parameters),
        };
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.host)
            .port(self.port)
            .tls(tls)
            .credentials(creds)
            .build();

        mailer
            .send(email)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to send email: {}", e)))?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTlsMode {
    Implicit,
    RequiredStarttls,
    OpportunisticStarttls,
}

pub fn smtp_tls_mode(mode: Option<&str>, disable_ssl: bool, port: u16) -> AppResult<SmtpTlsMode> {
    match mode {
        Some("Enable") => Ok(SmtpTlsMode::Implicit),
        Some("Disable") => Ok(SmtpTlsMode::OpportunisticStarttls),
        Some("Auto") => Ok(if port == 465 {
            SmtpTlsMode::Implicit
        } else {
            SmtpTlsMode::OpportunisticStarttls
        }),
        None | Some("") => Ok(if disable_ssl {
            SmtpTlsMode::OpportunisticStarttls
        } else if port == 465 {
            SmtpTlsMode::Implicit
        } else {
            SmtpTlsMode::RequiredStarttls
        }),
        _ => Err(AppError::Validation(
            "SMTP ssl_mode must be Auto, Enable, Disable or an empty legacy value".into(),
        )),
    }
}

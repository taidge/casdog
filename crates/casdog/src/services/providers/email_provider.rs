use crate::error::{AppError, AppResult};
use async_trait::async_trait;

/// Trait for email sending providers
#[async_trait]
pub trait EmailProviderTrait: Send + Sync {
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
    ) -> AppResult<()>;
}

/// SMTP email provider using lettre
pub struct SmtpEmailProvider {
    host: String,
    port: u16,
    username: String,
    password: String,
    from_address: String,
    use_ssl: bool,
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
        }
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
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
    ) -> AppResult<()> {
        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

        let email = Message::builder()
            .from(self.from_address.parse().map_err(|e| {
                AppError::Internal(format!("Invalid from address: {}", e))
            })?)
            .to(to.parse().map_err(|e| {
                AppError::Internal(format!("Invalid to address: {}", e))
            })?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body.to_string())
            .map_err(|e| AppError::Internal(format!("Failed to build email: {}", e)))?;

        let creds = Credentials::new(self.username.clone(), self.password.clone());

        let mailer = if self.use_ssl {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.host)
                .map_err(|e| AppError::Internal(format!("SMTP connection failed: {}", e)))?
                .port(self.port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.host)
                .map_err(|e| AppError::Internal(format!("SMTP connection failed: {}", e)))?
                .port(self.port)
                .credentials(creds)
                .build()
        };

        mailer
            .send(email)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to send email: {}", e)))?;

        Ok(())
    }
}

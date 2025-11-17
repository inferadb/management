use crate::error::{Error, Result};
use async_trait::async_trait;
use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// Email sender abstraction
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Send an email
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient email address
    /// * `subject` - Email subject line
    /// * `body_html` - HTML body content
    /// * `body_text` - Plain text body content (fallback)
    ///
    /// # Returns
    ///
    /// Ok(()) if email was sent successfully, or an error
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<()>;
}

/// SMTP configuration
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server host
    pub host: String,
    /// SMTP server port
    pub port: u16,
    /// SMTP username
    pub username: String,
    /// SMTP password
    pub password: String,
    /// From email address
    pub from_email: String,
    /// From name
    pub from_name: String,
}

/// SMTP-based email service implementation
pub struct SmtpEmailService {
    config: SmtpConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpEmailService {
    /// Create a new SMTP email service
    pub fn new(config: SmtpConfig) -> Result<Self> {
        let creds = Credentials::new(config.username.clone(), config.password.clone());

        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
            .map_err(|e| Error::Internal(format!("Failed to create SMTP transport: {}", e)))?
            .port(config.port)
            .credentials(creds)
            .build();

        Ok(Self { config, transport })
    }

    /// Get the from mailbox
    fn get_from_mailbox(&self) -> Result<Mailbox> {
        format!("{} <{}>", self.config.from_name, self.config.from_email)
            .parse()
            .map_err(|e| Error::Internal(format!("Invalid from address: {}", e)))
    }
}

#[async_trait]
impl EmailSender for SmtpEmailService {
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<()> {
        let from = self.get_from_mailbox()?;
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| Error::Validation(format!("Invalid recipient email: {}", e)))?;

        let email = Message::builder()
            .from(from)
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(format!("{}\n\n---\n\n{}", body_html, body_text))
            .map_err(|e| Error::Internal(format!("Failed to build email message: {}", e)))?;

        self.transport
            .send(email)
            .await
            .map_err(|e| Error::Internal(format!("Failed to send email: {}", e)))?;

        tracing::info!("Email sent to {} with subject: {}", to, subject);
        Ok(())
    }
}

/// Email service facade
pub struct EmailService {
    sender: Box<dyn EmailSender>,
}

impl EmailService {
    /// Create a new email service
    pub fn new(sender: Box<dyn EmailSender>) -> Self {
        Self { sender }
    }

    /// Send an email
    pub async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<()> {
        self.sender
            .send_email(to, subject, body_html, body_text)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock email sender for testing
    struct MockEmailSender {
        should_fail: bool,
    }

    #[async_trait]
    impl EmailSender for MockEmailSender {
        async fn send_email(
            &self,
            _to: &str,
            _subject: &str,
            _body_html: &str,
            _body_text: &str,
        ) -> Result<()> {
            if self.should_fail {
                Err(Error::Internal("Mock email send failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_email_service_success() {
        let sender = Box::new(MockEmailSender { should_fail: false });
        let service = EmailService::new(sender);

        let result = service
            .send_email("test@example.com", "Test Subject", "<h1>Test</h1>", "Test")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_email_service_failure() {
        let sender = Box::new(MockEmailSender { should_fail: true });
        let service = EmailService::new(sender);

        let result = service
            .send_email("test@example.com", "Test Subject", "<h1>Test</h1>", "Test")
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_smtp_config() {
        let config = SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "user".to_string(),
            password: "pass".to_string(),
            from_email: "noreply@example.com".to_string(),
            from_name: "Example App".to_string(),
        };

        assert_eq!(config.host, "smtp.example.com");
        assert_eq!(config.port, 587);
    }
}

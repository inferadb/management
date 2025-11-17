pub mod service;
pub mod templates;

pub use service::{EmailSender, EmailService, SmtpEmailService};
pub use templates::{EmailTemplate, VerificationEmailTemplate};

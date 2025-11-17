/// Email template trait
pub trait EmailTemplate {
    /// Get the email subject
    fn subject(&self) -> String;

    /// Get the HTML body
    fn html_body(&self) -> String;

    /// Get the plain text body
    fn text_body(&self) -> String;
}

/// Email verification template
pub struct VerificationEmailTemplate {
    /// User's name
    pub user_name: String,
    /// Verification link
    pub verification_link: String,
    /// Verification code (for manual entry)
    pub verification_code: String,
}

impl EmailTemplate for VerificationEmailTemplate {
    fn subject(&self) -> String {
        "Verify your email address".to_string()
    }

    fn html_body(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h1 style="color: #007bff; margin-top: 0;">Verify Your Email</h1>
        <p>Hi {},</p>
        <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{}"
               style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Verify Email Address
            </a>
        </div>

        <p>Or copy and paste this link into your browser:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; word-break: break-all;">
            <a href="{}" style="color: #007bff;">{}</a>
        </p>

        <p>If you prefer, you can also enter this verification code manually:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 18px; text-align: center; letter-spacing: 2px;">
            {}
        </p>

        <p style="color: #666; font-size: 14px; margin-top: 30px;">
            This link will expire in 24 hours. If you didn't request this verification, you can safely ignore this email.
        </p>
    </div>

    <p style="color: #999; font-size: 12px; text-align: center;">
        This is an automated message, please do not reply.
    </p>
</body>
</html>"#,
            self.user_name,
            self.verification_link,
            self.verification_link,
            self.verification_link,
            self.verification_code
        )
    }

    fn text_body(&self) -> String {
        format!(
            r#"Hi {},

Thanks for signing up! Please verify your email address.

Verification Link:
{}

Or enter this verification code manually:
{}

This link will expire in 24 hours. If you didn't request this verification, you can safely ignore this email.

---
This is an automated message, please do not reply.
"#,
            self.user_name, self.verification_link, self.verification_code
        )
    }
}

/// Password reset email template
pub struct PasswordResetEmailTemplate {
    /// User's name
    pub user_name: String,
    /// Reset link
    pub reset_link: String,
    /// Reset code (for manual entry)
    pub reset_code: String,
}

impl EmailTemplate for PasswordResetEmailTemplate {
    fn subject(&self) -> String {
        "Reset your password".to_string()
    }

    fn html_body(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h1 style="color: #dc3545; margin-top: 0;">Reset Your Password</h1>
        <p>Hi {},</p>
        <p>We received a request to reset your password. Click the button below to choose a new password:</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{}"
               style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Reset Password
            </a>
        </div>

        <p>Or copy and paste this link into your browser:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; word-break: break-all;">
            <a href="{}" style="color: #dc3545;">{}</a>
        </p>

        <p>If you prefer, you can also enter this reset code manually:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 18px; text-align: center; letter-spacing: 2px;">
            {}
        </p>

        <p style="color: #666; font-size: 14px; margin-top: 30px;">
            This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.
        </p>
    </div>

    <p style="color: #999; font-size: 12px; text-align: center;">
        This is an automated message, please do not reply.
    </p>
</body>
</html>"#,
            self.user_name, self.reset_link, self.reset_link, self.reset_link, self.reset_code
        )
    }

    fn text_body(&self) -> String {
        format!(
            r#"Hi {},

We received a request to reset your password.

Reset Link:
{}

Or enter this reset code manually:
{}

This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.

---
This is an automated message, please do not reply.
"#,
            self.user_name, self.reset_link, self.reset_code
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_email_template() {
        let template = VerificationEmailTemplate {
            user_name: "John Doe".to_string(),
            verification_link: "https://example.com/verify?token=abc123".to_string(),
            verification_code: "ABC123".to_string(),
        };

        assert_eq!(template.subject(), "Verify your email address");
        assert!(template.html_body().contains("John Doe"));
        assert!(template
            .html_body()
            .contains("https://example.com/verify?token=abc123"));
        assert!(template.html_body().contains("ABC123"));
        assert!(template.text_body().contains("John Doe"));
        assert!(template
            .text_body()
            .contains("https://example.com/verify?token=abc123"));
        assert!(template.text_body().contains("ABC123"));
    }

    #[test]
    fn test_password_reset_email_template() {
        let template = PasswordResetEmailTemplate {
            user_name: "Jane Smith".to_string(),
            reset_link: "https://example.com/reset?token=xyz789".to_string(),
            reset_code: "XYZ789".to_string(),
        };

        assert_eq!(template.subject(), "Reset your password");
        assert!(template.html_body().contains("Jane Smith"));
        assert!(template
            .html_body()
            .contains("https://example.com/reset?token=xyz789"));
        assert!(template.html_body().contains("XYZ789"));
        assert!(template.text_body().contains("Jane Smith"));
        assert!(template
            .text_body()
            .contains("https://example.com/reset?token=xyz789"));
        assert!(template.text_body().contains("XYZ789"));
    }
}

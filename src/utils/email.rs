use crate::errors::AppError;
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

/// Build an SMTP mailer.
///
/// When `no_tls` is `true` (e.g. for MailHog), an unencrypted transport is
/// used. Otherwise STARTTLS is negotiated. Credentials are optional.
pub fn build_mailer(
    host: &str,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    no_tls: bool,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, AppError> {
    let builder = if no_tls {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(port)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| AppError::Email(e.to_string()))?
            .port(port)
    };

    let builder = if let (Some(u), Some(p)) = (username, password) {
        builder.credentials(Credentials::new(u, p))
    } else {
        builder
    };

    Ok(builder.build())
}

/// Send an HTML confirmation email containing a clickable activation link.
pub async fn send_confirmation_email(
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &str,
    to_email: &str,
    base_url: &str,
    token: &str,
) -> Result<(), AppError> {
    let link = format!("{}/auth/confirm-email?token={}", base_url, token);

    let body = format!(
        "<p>Click the link below to confirm your email address and activate your account:</p>\
         <p><a href=\"{link}\">{link}</a></p>",
        link = link
    );

    let email = Message::builder()
        .from(
            from.parse()
                .map_err(|e: lettre::address::AddressError| AppError::Email(e.to_string()))?,
        )
        .to(
            to_email
                .parse()
                .map_err(|e: lettre::address::AddressError| AppError::Email(e.to_string()))?,
        )
        .subject("Confirm your email address")
        .header(ContentType::TEXT_HTML)
        .body(body)
        .map_err(|e| AppError::Email(e.to_string()))?;

    mailer
        .send(email)
        .await
        .map_err(|e| AppError::Email(e.to_string()))?;

    Ok(())
}

/// Send an HTML password-reset email containing a clickable reset link.
pub async fn send_password_reset_email(
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &str,
    to_email: &str,
    base_url: &str,
    token: &str,
) -> Result<(), AppError> {
    let link = format!("{}/auth/password-reset?token={}", base_url, token);

    let body = format!(
        "<p>Click the link below to reset your password:</p>\
         <p><a href=\"{link}\">{link}</a></p>\
         <p>This link expires in 30 minutes. If you did not request a password reset, you can safely ignore this email.</p>",
        link = link
    );

    let email = Message::builder()
        .from(
            from.parse()
                .map_err(|e: lettre::address::AddressError| AppError::Email(e.to_string()))?,
        )
        .to(
            to_email
                .parse()
                .map_err(|e: lettre::address::AddressError| AppError::Email(e.to_string()))?,
        )
        .subject("Reset your password")
        .header(ContentType::TEXT_HTML)
        .body(body)
        .map_err(|e| AppError::Email(e.to_string()))?;

    mailer
        .send(email)
        .await
        .map_err(|e| AppError::Email(e.to_string()))?;

    Ok(())
}

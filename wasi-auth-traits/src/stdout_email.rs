use crate::{AuthError, EmailSender};

/// A no-op [`EmailSender`] that prints emails to **stdout**.
///
/// Intended for **development and testing** only. Each call to
/// [`send_email`](EmailSender::send_email) writes a human-readable
/// representation of the message (recipient, subject, body) surrounded by
/// visual delimiters so it is easy to spot in log output.
///
/// This sender is always available (no feature flag required) and never fails.
#[derive(Debug, Clone)]
pub struct StdoutEmail;

impl Default for StdoutEmail {
    fn default() -> Self {
        Self::new()
    }
}

impl StdoutEmail {
    /// Creates a new `StdoutEmail` instance.
    pub fn new() -> Self {
        Self
    }
}

impl EmailSender for StdoutEmail {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        println!("====================[ OUTBOUND EMAIL ]====================");
        println!("To:      {}", to);
        println!("Subject: {}", subject);
        println!("Content:\n{}", body);
        println!("==========================================================");
        Ok(())
    }
}

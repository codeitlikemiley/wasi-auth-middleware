use crate::{AuthError, EmailSender};

#[derive(Debug, Clone)]
pub struct StdoutEmail;

impl Default for StdoutEmail {
    fn default() -> Self {
        Self::new()
    }
}

impl StdoutEmail {
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

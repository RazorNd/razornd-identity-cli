use crate::oidc::token_provider::TokenProviderError;
use openidconnect::url::Url;

/// Opens an authorization URL in a browser.
pub trait Browser: Send + Sync {
    fn open(&self, authorization_url: &Url) -> Result<(), TokenProviderError>;
}

/// Opens URLs using the operating system's default browser.
pub struct SystemBrowser;

impl Browser for SystemBrowser {
    fn open(&self, authorization_url: &Url) -> Result<(), TokenProviderError> {
        webbrowser::open(authorization_url.as_str())?;
        Ok(())
    }
}

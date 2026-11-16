use openidconnect::url::Url;
use std::io;

/// Opens an authorization URL in a browser.
pub trait Browser: Send + Sync {
    fn open(&self, authorization_url: &Url) -> Result<(), io::Error>;
}

/// Opens URLs using the operating system's default browser.
pub struct SystemBrowser;

impl Browser for SystemBrowser {
    fn open(&self, authorization_url: &Url) -> Result<(), io::Error> {
        webbrowser::open(authorization_url.as_str())?;
        Ok(())
    }
}

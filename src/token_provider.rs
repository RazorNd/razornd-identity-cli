use async_trait::async_trait;
use std::error::Error;

pub type TokenProviderError = Box<dyn Error + Send + Sync>;

/// Access token returned by a [`TokenProvider`].
///
/// Its debug representation intentionally does not reveal the token value.
pub struct AccessToken(String);

impl AccessToken {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Exposes the token for use in an `Authorization` header.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccessToken([REDACTED])")
    }
}

/// Provides an access token suitable for calling the identity service.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn access_token(&self) -> Result<AccessToken, TokenProviderError>;
}

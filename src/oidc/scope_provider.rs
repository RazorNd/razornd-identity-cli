use async_trait::async_trait;
use openidconnect::Scope;
use std::error::Error;

/// Provides advertised scopes without starting user authorization.
#[async_trait]
pub trait SupportedScopesProvider: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    /// Returns `None` if the provider did not advertise `scopes_supported`.
    async fn supported_scopes(&self) -> Result<Option<&[Scope]>, Self::Error>;
}

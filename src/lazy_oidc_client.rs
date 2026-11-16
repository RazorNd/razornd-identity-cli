use crate::{
    oidc_client::{OidcClient, OidcClientConfig},
    token_provider::{AccessToken, TokenProvider, TokenProviderError},
};
use async_trait::async_trait;
use openidconnect::{ClientId, IssuerUrl, RedirectUrl};
use std::net::SocketAddr;
use tokio::sync::{Mutex, OnceCell};

/// Lazily initializes an [`OidcClient`] on the first token request.
///
/// Concurrent first requests share the same initialization; if discovery
/// fails, a later request can retry it.
pub struct LazyOidcClient {
    config: Mutex<Option<OidcClientConfig>>,
    client: OnceCell<OidcClient>,
    http_client: reqwest::Client,
}

impl LazyOidcClient {
    /// Creates the wrapper without contacting the OIDC provider.
    pub fn new(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            config: Mutex::new(Some(OidcClientConfig::new(
                issuer_url,
                client_id,
                redirect_url,
                callback_addr,
            ))),
            client: OnceCell::new(),
            http_client,
        }
    }
}

#[async_trait]
impl TokenProvider for LazyOidcClient {
    async fn access_token(&self) -> Result<AccessToken, TokenProviderError> {
        let client = self
            .client
            .get_or_try_init(|| async {
                let config = self.config.lock().await.take().ok_or(
                    "OIDC client initialization already failed; configuration was consumed",
                )?;
                OidcClient::new(config, self.http_client.clone()).await
            })
            .await?;

        client.access_token().await
    }
}

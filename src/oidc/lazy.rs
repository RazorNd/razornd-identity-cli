use super::{
    callback_server::{CallbackServer, LocalCallbackServer},
    client::{OidcClient, OidcClientConfig},
};
use crate::oidc::{AccessToken, TokenProvider, TokenProviderError};
use async_trait::async_trait;
use openidconnect::{ClientId, IssuerUrl, RedirectUrl};
use std::net::SocketAddr;
use tokio::sync::{Mutex, OnceCell};

/// Lazily initializes an [`OidcClient`] on the first token request.
///
/// Concurrent first requests share the same initialization; if discovery
/// fails, a later request can retry it.
pub struct LazyOidcClient<C = LocalCallbackServer> {
    config: Mutex<Option<OidcClientConfig>>,
    callback_server: Mutex<Option<C>>,
    client: OnceCell<OidcClient<C>>,
    http_client: reqwest::Client,
}

impl LazyOidcClient<LocalCallbackServer> {
    /// Creates the wrapper without contacting the OIDC provider.
    pub fn new(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Self {
        Self::with_callback_server(
            issuer_url,
            client_id,
            redirect_url,
            callback_addr,
            http_client,
            LocalCallbackServer::new(callback_addr),
        )
    }
}

impl<C: CallbackServer> LazyOidcClient<C> {
    /// Creates the wrapper with a custom callback server, without contacting
    /// the OIDC provider.
    pub fn with_callback_server(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
        callback_server: C,
    ) -> Self {
        Self {
            config: Mutex::new(Some(OidcClientConfig::new(
                issuer_url,
                client_id,
                redirect_url,
                callback_addr,
            ))),
            callback_server: Mutex::new(Some(callback_server)),
            client: OnceCell::new(),
            http_client,
        }
    }
}

#[async_trait]
impl<C: CallbackServer> TokenProvider for LazyOidcClient<C> {
    async fn access_token(&self) -> Result<AccessToken, TokenProviderError> {
        let client = self
            .client
            .get_or_try_init(|| async {
                let config = self.config.lock().await.take().ok_or(
                    "OIDC client initialization already failed; configuration was consumed",
                )?;
                let callback_server = self.callback_server.lock().await.take().ok_or(
                    "OIDC client initialization already failed; callback server was consumed",
                )?;
                OidcClient::with_callback_server(config, self.http_client.clone(), callback_server)
                    .await
            })
            .await?;

        client.access_token().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::tests::support::{SuccessfulCallbackServer, mount_oidc_provider};
    use wiremock::MockServer;

    #[tokio::test]
    async fn creating_lazy_client_does_not_call_issuer() {
        let server = MockServer::start().await;
        mount_oidc_provider(&server, 0, 0).await;

        let _client = LazyOidcClient::new(
            IssuerUrl::new(server.uri()).unwrap(),
            ClientId::new("test-client".to_owned()),
            RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned()).unwrap(),
            "127.0.0.1:54321".parse().unwrap(),
            reqwest::Client::new(),
        );

        server.verify().await;
    }

    #[tokio::test]
    async fn multiple_token_requests_discover_issuer_only_once() -> Result<(), TokenProviderError> {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount_oidc_provider(&server, 1, 2).await;

        let client = LazyOidcClient::with_callback_server(
            IssuerUrl::new(issuer)?,
            ClientId::new("test-client".to_owned()),
            RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned())?,
            "127.0.0.1:54321".parse()?,
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            SuccessfulCallbackServer,
        );

        for _ in 0..2 {
            let access_token = client.access_token().await?;
            assert_eq!(access_token.expose_secret(), "test-access-token");
        }

        server.verify().await;
        Ok(())
    }
}

use super::{
    browser::{Browser, SystemBrowser},
    callback_server::{CallbackServer, LocalCallbackServer},
    client::OidcClient,
};
use crate::oidc::{AccessToken, TokenProvider, TokenProviderError};
use async_trait::async_trait;
use openidconnect::{ClientId, IssuerUrl, RedirectUrl};
use std::net::SocketAddr;
use tokio::sync::{Mutex, OnceCell};

struct OidcClientConfig<C, B> {
    issuer_url: IssuerUrl,
    client_id: ClientId,
    redirect_url: RedirectUrl,
    http_client: reqwest::Client,
    callback_server: C,
    browser: B,
}

/// Lazily initializes an [`OidcClient`] on the first token request.
///
/// Concurrent first requests share the same initialization; if discovery
/// fails, a later request can retry it.
pub struct LazyOidcClient<C = LocalCallbackServer, B = SystemBrowser> {
    config: Mutex<Option<OidcClientConfig<C, B>>>,
    client: OnceCell<OidcClient<C, B>>,
}

impl LazyOidcClient<LocalCallbackServer, SystemBrowser> {
    /// Creates the wrapper without contacting the OIDC provider.
    pub fn new(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Self {
        Self::with_components(
            issuer_url,
            client_id,
            redirect_url,
            http_client,
            LocalCallbackServer::new(callback_addr),
            SystemBrowser,
        )
    }
}

impl<C: CallbackServer> LazyOidcClient<C, SystemBrowser> {
    /// Creates the wrapper with a custom callback server, without contacting
    /// the OIDC provider.
    pub fn with_callback_server(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
    ) -> Self {
        Self::with_components(
            issuer_url,
            client_id,
            redirect_url,
            http_client,
            callback_server,
            SystemBrowser,
        )
    }
}

impl<C: CallbackServer, B: Browser> LazyOidcClient<C, B> {
    /// Creates the wrapper with custom callback server and browser.
    pub fn with_components(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
        browser: B,
    ) -> Self {
        Self {
            config: Mutex::new(Some(OidcClientConfig {
                issuer_url,
                client_id,
                redirect_url,
                http_client,
                callback_server,
                browser,
            })),
            client: OnceCell::new(),
        }
    }
}

#[async_trait]
impl<C: CallbackServer, B: Browser> TokenProvider<TokenProviderError> for LazyOidcClient<C, B> {
    async fn access_token(&self) -> Result<AccessToken, TokenProviderError> {
        let client = self
            .client
            .get_or_try_init(|| async {
                let config = self.config.lock().await.take().ok_or(
                    "OIDC client initialization already failed; configuration was consumed",
                )?;
                OidcClient::with_components(
                    config.issuer_url,
                    config.client_id,
                    config.redirect_url,
                    config.http_client,
                    config.callback_server,
                    config.browser,
                )
                .await
                .map_err(|error| Box::new(error) as TokenProviderError)
            })
            .await?;

        client
            .access_token()
            .await
            .map_err(|error| Box::new(error) as TokenProviderError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::tests::support::{mount_oidc_provider, successful_callback_components};
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

        let redirect_url = RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned())?;
        let (callback_server, browser) = successful_callback_components(&redirect_url);
        let client = LazyOidcClient::with_components(
            IssuerUrl::new(issuer)?,
            ClientId::new("test-client".to_owned()),
            redirect_url,
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            callback_server,
            browser,
        );

        for _ in 0..2 {
            let access_token = client.access_token().await?;
            assert_eq!(access_token.expose_secret(), "test-access-token");
        }

        server.verify().await;
        Ok(())
    }
}

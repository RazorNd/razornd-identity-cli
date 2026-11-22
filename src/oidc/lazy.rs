use super::{
    browser::{Browser, SystemBrowser},
    callback_server::{CallbackServer, LocalCallbackServer},
    client::OidcClient,
};
use crate::oidc::{Authorization, AuthorizationProvider};
use async_trait::async_trait;
use openidconnect::{ClientId, IssuerUrl, RedirectUrl, Scope};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::sync::{Mutex, OnceCell};

#[derive(Debug, Error)]
pub enum LazyOidcClientError {
    #[error("failed to initialize OIDC client: {0}")]
    Initialization(#[source] LazyOidcClientInitError),
    #[error("OIDC token request failed: {0}")]
    TokenRequest(#[source] super::client::OidcClientError),
}

#[derive(Debug, Error)]
pub enum LazyOidcClientInitError {
    #[error(transparent)]
    OidcClient(#[from] super::client::OidcClientInitError),
    #[error("OIDC client configuration is unavailable after a previous initialization failure")]
    ConfigurationUnavailable,
}

struct OidcClientConfig<C, B> {
    issuer_url: IssuerUrl,
    client_id: ClientId,
    scopes: Vec<Scope>,
    redirect_url: RedirectUrl,
    http_client: reqwest::Client,
    callback_server: C,
    browser: B,
}

/// Lazily initializes an [`OidcClient`] on the first token request.
///
/// Concurrent first requests share the same initialization; if discovery
/// fails, the initialization error is returned to the caller.
pub struct LazyOidcClient<C = LocalCallbackServer, B = SystemBrowser> {
    config: Mutex<Option<OidcClientConfig<C, B>>>,
    client: OnceCell<OidcClient<C, B>>,
}

impl LazyOidcClient<LocalCallbackServer, SystemBrowser> {
    /// Creates the wrapper without contacting the OIDC provider.
    pub fn new(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        scopes: Vec<Scope>,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Self {
        Self::with_components(
            issuer_url,
            client_id,
            scopes,
            redirect_url,
            http_client,
            LocalCallbackServer::new(callback_addr),
            SystemBrowser,
        )
    }
}

impl<C: CallbackServer, B: Browser> LazyOidcClient<C, B> {
    /// Creates the wrapper with custom callback server and browser.
    pub fn with_components(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        scopes: Vec<Scope>,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
        browser: B,
    ) -> Self {
        Self {
            config: Mutex::new(Some(OidcClientConfig {
                issuer_url,
                client_id,
                scopes,
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
impl<C, B> AuthorizationProvider for LazyOidcClient<C, B>
where
    C: CallbackServer,
    B: Browser,
{
    type Error = LazyOidcClientError;

    async fn authorize(&self) -> Result<Authorization, Self::Error> {
        let client = self
            .client
            .get_or_try_init(|| async {
                let config = self.config.lock().await.take().ok_or_else(|| {
                    LazyOidcClientError::Initialization(
                        LazyOidcClientInitError::ConfigurationUnavailable,
                    )
                })?;
                OidcClient::with_components(
                    config.issuer_url,
                    config.client_id,
                    config.scopes,
                    config.redirect_url,
                    config.http_client,
                    config.callback_server,
                    config.browser,
                )
                .await
                .map_err(|error| {
                    LazyOidcClientError::Initialization(LazyOidcClientInitError::from(error))
                })
            })
            .await?;

        client
            .authorize()
            .await
            .map_err(LazyOidcClientError::TokenRequest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::{
        OidcClientError, OidcClientInitError, TokenProvider,
        tests::support::{mount_oidc_provider, successful_callback_components},
    };
    use std::net::TcpListener;
    use wiremock::MockServer;

    #[tokio::test]
    async fn creating_lazy_client_does_not_call_issuer() {
        let server = MockServer::start().await;
        mount_oidc_provider(&server, 0, 0).await;

        let _client = LazyOidcClient::new(
            IssuerUrl::new(server.uri()).unwrap(),
            ClientId::new("test-client".to_owned()),
            vec![Scope::new("openid".to_owned())],
            RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned()).unwrap(),
            "127.0.0.1:54321".parse().unwrap(),
            reqwest::Client::new(),
        );

        server.verify().await;
    }

    #[tokio::test]
    async fn multiple_token_requests_discover_issuer_only_once() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount_oidc_provider(&server, 1, 2).await;

        let redirect_url = RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned())?;
        let (callback_server, browser) = successful_callback_components(&redirect_url, "openid");
        let client = LazyOidcClient::with_components(
            IssuerUrl::new(issuer)?,
            ClientId::new("test-client".to_owned()),
            vec![Scope::new("openid".to_owned())],
            redirect_url,
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            callback_server,
            browser,
        );

        let authorization = client.authorize().await?;
        assert_eq!(
            authorization.access_token().expose_secret(),
            "test-access-token"
        );
        assert_eq!(
            authorization
                .refresh_token()
                .map(|token| token.expose_secret()),
            Some("test-refresh-token")
        );
        assert_eq!(
            authorization.expires_in(),
            Some(std::time::Duration::from_secs(3600))
        );

        let access_token = client.access_token().await?;
        assert_eq!(access_token.expose_secret(), "test-access-token");

        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn access_token_reports_client_initialization_error() {
        let server = MockServer::start().await;
        let client = LazyOidcClient::new(
            IssuerUrl::new(server.uri()).unwrap(),
            ClientId::new("test-client".to_owned()),
            vec![Scope::new("openid".to_owned())],
            RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned()).unwrap(),
            "127.0.0.1:54321".parse().unwrap(),
            reqwest::Client::new(),
        );

        assert!(matches!(
            client.access_token().await,
            Err(LazyOidcClientError::Initialization(
                LazyOidcClientInitError::OidcClient(OidcClientInitError::Discovery(_))
            ))
        ));
    }

    #[tokio::test]
    async fn access_token_reports_client_request_error() {
        let server = MockServer::start().await;
        mount_oidc_provider(&server, 1, 0).await;
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let callback_addr = occupied.local_addr().unwrap();
        let client = LazyOidcClient::with_components(
            IssuerUrl::new(server.uri()).unwrap(),
            ClientId::new("test-client".to_owned()),
            vec![Scope::new("openid".to_owned())],
            RedirectUrl::new(format!("http://{callback_addr}/callback")).unwrap(),
            reqwest::Client::new(),
            LocalCallbackServer::new(callback_addr),
            SystemBrowser,
        );

        assert!(matches!(
            client.access_token().await,
            Err(LazyOidcClientError::TokenRequest(
                OidcClientError::CallbackServer(_)
            ))
        ));
        server.verify().await;
    }
}

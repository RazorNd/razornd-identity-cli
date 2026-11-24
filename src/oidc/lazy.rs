use super::{
    browser::{Browser, SystemBrowser},
    callback_server::{CallbackServer, LocalCallbackServer},
    client::{OidcClient, discover_provider},
};
use crate::oidc::{Authorization, AuthorizationProvider, SupportedScopesProvider};
use async_trait::async_trait;
use openidconnect::{ClientId, IssuerUrl, RedirectUrl, Scope};
use std::{net::SocketAddr, sync::Arc};
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

/// Lazily initializes an [`OidcClient`] on the first discovery or token request.
///
/// Clones and concurrent first requests share successful initialization.
pub struct LazyOidcClient<C = LocalCallbackServer, B = SystemBrowser> {
    state: Arc<LazyOidcClientState<C, B>>,
}

struct LazyOidcClientState<C, B> {
    config: Mutex<Option<OidcClientConfig<C, B>>>,
    client: OnceCell<OidcClient<C, B>>,
}

impl<C, B> Clone for LazyOidcClient<C, B> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
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
            state: Arc::new(LazyOidcClientState {
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
            }),
        }
    }

    async fn initialized(&self) -> Result<&OidcClient<C, B>, LazyOidcClientInitError> {
        self.state
            .client
            .get_or_try_init(|| async {
                let mut pending = self.state.config.lock().await;
                let config = pending
                    .as_ref()
                    .ok_or(LazyOidcClientInitError::ConfigurationUnavailable)?;
                let provider =
                    discover_provider(config.issuer_url.clone(), &config.http_client).await?;

                // Retain configuration on failure or cancellation so authorization can retry.
                let config = pending
                    .take()
                    .ok_or(LazyOidcClientInitError::ConfigurationUnavailable)?;
                Ok(OidcClient::from_provider_metadata(
                    provider,
                    config.client_id,
                    config.scopes,
                    config.redirect_url,
                    config.http_client,
                    config.callback_server,
                    config.browser,
                ))
            })
            .await
    }
}

#[async_trait]
impl<C: CallbackServer, B: Browser> SupportedScopesProvider for LazyOidcClient<C, B> {
    type Error = LazyOidcClientInitError;

    async fn supported_scopes(&self) -> Result<Option<&[Scope]>, Self::Error> {
        self.initialized()
            .await?
            .supported_scopes()
            .await
            .map_err(|never| match never {})
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
            .initialized()
            .await
            .map_err(LazyOidcClientError::Initialization)?;

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
        tests::support::{
            mount_oidc_provider, mount_oidc_provider_with_scopes, successful_callback_components,
        },
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
    async fn supported_scopes_and_token_requests_share_discovery() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount_oidc_provider_with_scopes(&server, 1, 2, Some(&["openid", "email"])).await;

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

        assert_eq!(
            client.clone().supported_scopes().await?,
            Some(
                &[
                    Scope::new("openid".to_owned()),
                    Scope::new("email".to_owned())
                ][..]
            )
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| { request.url.path() != "/token" }),
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
    async fn missing_scopes_are_optional_and_failed_discovery_can_be_retried() -> anyhow::Result<()>
    {
        let server = MockServer::start().await;
        let client = LazyOidcClient::new(
            IssuerUrl::new(server.uri())?,
            ClientId::new("test-client".to_owned()),
            vec![Scope::new("openid".to_owned())],
            RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned())?,
            "127.0.0.1:54321".parse()?,
            reqwest::Client::new(),
        );
        assert!(matches!(
            client.supported_scopes().await,
            Err(LazyOidcClientInitError::OidcClient(
                OidcClientInitError::Discovery(_)
            ))
        ));

        mount_oidc_provider(&server, 1, 0).await;
        assert_eq!(client.supported_scopes().await?, None);
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

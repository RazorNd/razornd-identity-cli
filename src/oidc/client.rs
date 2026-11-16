use crate::oidc::{
    AccessToken, Browser, CallbackListenError, CallbackListener, CallbackReceiveError,
    CallbackServer, LocalCallbackServer, SystemBrowser, TokenProvider,
};
use async_trait::async_trait;
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, ConfigurationError, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpClientError, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, RequestTokenError, StandardErrorResponse,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreErrorResponseType, CoreProviderMetadata},
};
use std::io;
use std::net::SocketAddr;
use thiserror::Error;

type ConfiguredCoreClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

type TokenEndpointError = RequestTokenError<
    HttpClientError<reqwest::Error>,
    StandardErrorResponse<CoreErrorResponseType>,
>;

#[derive(Debug, Error)]
pub enum OidcClientInitError {
    #[error("OIDC provider discovery failed: {0}")]
    Discovery(String),
}

#[derive(Debug, Error)]
pub enum OidcClientError {
    #[error("Failed to start callback listener: {0}")]
    CallbackServer(#[source] CallbackListenError),
    #[error("Failed to open authorization URL in browser: {0}")]
    Browser(#[source] io::Error),
    #[error("Failed to receive authorization callback: {0}")]
    CallbackReceive(#[source] CallbackReceiveError),
    #[error("OAuth state did not match")]
    InvalidState,
    #[error("Authorization provider rejected the request: {0}")]
    ProviderRejected(String),
    #[error("Authorization callback did not contain an authorization code")]
    MissingAuthorizationCode,
    #[error("Failed to configure token exchange: {0}")]
    TokenExchangeConfiguration(#[source] ConfigurationError),
    #[error("Token endpoint request failed: {0}")]
    TokenEndpoint(#[source] TokenEndpointError),
    #[error("ID token validation failed: {0}")]
    IdTokenValidation(#[source] ClaimsVerificationError),
}

/// OIDC Authorization Code + PKCE token provider for a native CLI client.
///
/// This prototype performs an interactive login on every call. It does not
/// cache tokens or use refresh tokens; a store decorator can add that later.
pub struct OidcClient<C = LocalCallbackServer, B = SystemBrowser> {
    oidc_client: ConfiguredCoreClient,
    http_client: reqwest::Client,
    redirect_url: RedirectUrl,
    callback_server: C,
    browser: B,
}

impl OidcClient<LocalCallbackServer, SystemBrowser> {
    /// Builds an OIDC client using the local callback server and system browser.
    pub async fn new(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Result<Self, OidcClientInitError> {
        Self::with_components(
            issuer_url,
            client_id,
            redirect_url,
            http_client,
            LocalCallbackServer::new(callback_addr),
            SystemBrowser,
        )
        .await
    }

    /// Builds an OIDC client from individual parameters.
    pub async fn from_params(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Result<Self, OidcClientInitError> {
        Self::new(
            issuer_url,
            client_id,
            redirect_url,
            callback_addr,
            http_client,
        )
        .await
    }
}

impl<C: CallbackServer> OidcClient<C, SystemBrowser> {
    /// Builds an OIDC client with a custom callback server.
    pub async fn with_callback_server(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
    ) -> Result<Self, OidcClientInitError> {
        Self::with_components(
            issuer_url,
            client_id,
            redirect_url,
            http_client,
            callback_server,
            SystemBrowser,
        )
        .await
    }
}

impl<C, B> OidcClient<C, B>
where
    C: CallbackServer,
    B: Browser,
{
    /// Builds an OIDC client with custom callback server and browser.
    pub async fn with_components(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
        browser: B,
    ) -> Result<Self, OidcClientInitError> {
        let provider = CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .map_err(|error| OidcClientInitError::Discovery(error.to_string()))?;

        let oidc_client = CoreClient::from_provider_metadata(provider, client_id, None)
            .set_redirect_uri(redirect_url.clone());

        Ok(Self {
            oidc_client,
            http_client,
            redirect_url,
            callback_server,
            browser,
        })
    }

    async fn authorize(&self) -> Result<AccessToken, OidcClientError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorization_url, csrf_state, nonce) = self
            .oidc_client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge)
            .url();

        let listener = self
            .callback_server
            .listen(&self.redirect_url)
            .map_err(OidcClientError::CallbackServer)?;
        self.browser
            .open(&authorization_url)
            .map_err(OidcClientError::Browser)?;
        println!("Ожидание ответа от провайдера на {} ...", self.redirect_url);
        let callback = listener
            .receive()
            .await
            .map_err(OidcClientError::CallbackReceive)?;

        if callback.state.as_deref() != Some(csrf_state.secret()) {
            return Err(OidcClientError::InvalidState);
        }
        if let Some(error) = callback.error {
            return Err(OidcClientError::ProviderRejected(error));
        }

        let code = callback
            .code
            .ok_or(OidcClientError::MissingAuthorizationCode)?;
        let token_request = self
            .oidc_client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(OidcClientError::TokenExchangeConfiguration)?
            .set_pkce_verifier(pkce_verifier);
        let token_response = token_request
            .request_async(&self.http_client)
            .await
            .map_err(OidcClientError::TokenEndpoint)?;

        if let Some(id_token) = token_response.id_token() {
            id_token
                .claims(&self.oidc_client.id_token_verifier(), &nonce)
                .map_err(OidcClientError::IdTokenValidation)?;
        }

        Ok(AccessToken::new(
            token_response.access_token().secret().to_owned(),
        ))
    }
}

#[async_trait]
impl<C, B> TokenProvider<OidcClientError> for OidcClient<C, B>
where
    C: CallbackServer,
    B: Browser,
{
    async fn access_token(&self) -> Result<AccessToken, OidcClientError> {
        self.authorize().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::tests::support::{
        BrowserMode, CallbackMode, error_test_server, invalid_id_token, mount_error_test_provider,
        mount_oidc_provider, successful_callback_components, test_client,
    };
    use wiremock::MockServer;

    #[tokio::test]
    async fn access_token_returns_token_after_authorization_code_flow() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount_oidc_provider(&server, 1, 1).await;

        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let redirect_url = RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned())?;
        let (callback_server, browser) = successful_callback_components(&redirect_url);
        let client = OidcClient::with_components(
            IssuerUrl::new(issuer)?,
            ClientId::new("test-client".to_owned()),
            redirect_url,
            http_client,
            callback_server,
            browser,
        )
        .await?;

        let access_token = client.access_token().await?;
        assert_eq!(access_token.expose_secret(), "test-access-token");

        Ok(())
    }

    #[tokio::test]
    async fn access_token_returns_callback_server_error() {
        let (_server, issuer) =
            error_test_server(true, 500, serde_json::json!({"error": "server_error"})).await;
        let client = test_client(issuer, CallbackMode::ListenError, BrowserMode::Success)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::CallbackServer(_))
        ));
    }

    #[tokio::test]
    async fn access_token_returns_browser_error() {
        let (_server, issuer) =
            error_test_server(true, 500, serde_json::json!({"error": "server_error"})).await;
        let client = test_client(issuer, CallbackMode::Success, BrowserMode::Error)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::Browser(_))
        ));
    }

    #[tokio::test]
    async fn access_token_returns_callback_receive_error() {
        let (_server, issuer) =
            error_test_server(true, 500, serde_json::json!({"error": "server_error"})).await;
        let client = test_client(issuer, CallbackMode::ReceiveError, BrowserMode::Success)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::CallbackReceive(_))
        ));
    }

    #[tokio::test]
    async fn access_token_rejects_invalid_state() {
        let (_server, issuer) =
            error_test_server(true, 500, serde_json::json!({"error": "server_error"})).await;
        let client = test_client(issuer, CallbackMode::InvalidState, BrowserMode::Success)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::InvalidState)
        ));
    }

    #[tokio::test]
    async fn access_token_reports_provider_rejection() {
        let (_server, issuer) =
            error_test_server(true, 500, serde_json::json!({"error": "server_error"})).await;
        let client = test_client(issuer, CallbackMode::ProviderRejected, BrowserMode::Success)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::ProviderRejected(_))
        ));
    }

    #[tokio::test]
    async fn access_token_reports_missing_authorization_code() {
        let (_server, issuer) =
            error_test_server(true, 500, serde_json::json!({"error": "server_error"})).await;
        let client = test_client(issuer, CallbackMode::MissingCode, BrowserMode::Success)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::MissingAuthorizationCode)
        ));
    }

    #[tokio::test]
    async fn access_token_reports_token_endpoint_error() {
        let (_server, issuer) =
            error_test_server(true, 500, serde_json::json!({"error": "server_error"})).await;
        let client = test_client(issuer, CallbackMode::Success, BrowserMode::Success)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::TokenEndpoint(_))
        ));
    }

    #[tokio::test]
    async fn access_token_reports_missing_token_endpoint_configuration() {
        let (_server, issuer) = error_test_server(false, 200, serde_json::Value::Null).await;
        let client = test_client(issuer, CallbackMode::Success, BrowserMode::Success)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::TokenExchangeConfiguration(_))
        ));
    }

    #[tokio::test]
    async fn access_token_reports_invalid_id_token() {
        let id_token_server = MockServer::start().await;
        let id_token_issuer = id_token_server.uri();
        let id_token = invalid_id_token(&id_token_issuer, "test-client");
        mount_error_test_provider(
            &id_token_server,
            true,
            200,
            serde_json::json!({
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token
            }),
        )
        .await;
        let client = test_client(id_token_issuer, CallbackMode::Success, BrowserMode::Success)
            .await
            .unwrap();
        assert!(matches!(
            client.access_token().await,
            Err(OidcClientError::IdTokenValidation(_))
        ));
    }
}

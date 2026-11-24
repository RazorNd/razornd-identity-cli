use crate::oidc::{
    AccessToken, Authorization, AuthorizationProvider, Browser, CallbackListenError,
    CallbackListener, CallbackReceiveError, CallbackServer, LocalCallbackServer, RefreshToken,
    SupportedScopesProvider, SystemBrowser,
};
use async_trait::async_trait;
use openidconnect::{
    AccessToken as OAuthAccessToken, AuthorizationCode, ClaimsVerificationError, ClientId,
    ConfigurationError, CsrfToken, EmptyAdditionalClaims, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, HttpClientError, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    RedirectUrl, RefreshToken as OAuthRefreshToken, RequestTokenError, Scope,
    StandardErrorResponse, TokenResponse,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
        CoreGenderClaim, CoreIdToken, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRevocableToken,
        CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
    },
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

type ConfiguredCoreClient = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    OwnedCoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Debug, Deserialize, Serialize)]
struct OwnedCoreTokenResponse {
    access_token: OAuthAccessToken,
    token_type: CoreTokenType,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<OAuthRefreshToken>,
    #[serde(default)]
    id_token: Option<CoreIdToken>,
}

impl OAuth2TokenResponse for OwnedCoreTokenResponse {
    type TokenType = CoreTokenType;

    fn access_token(&self) -> &OAuthAccessToken {
        &self.access_token
    }

    fn token_type(&self) -> &Self::TokenType {
        &self.token_type
    }

    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }

    fn refresh_token(&self) -> Option<&OAuthRefreshToken> {
        self.refresh_token.as_ref()
    }

    fn scopes(&self) -> Option<&Vec<Scope>> {
        None
    }
}

impl
    TokenResponse<
        EmptyAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    > for OwnedCoreTokenResponse
{
    fn id_token(&self) -> Option<&CoreIdToken> {
        self.id_token.as_ref()
    }
}

type TokenEndpointError = RequestTokenError<
    HttpClientError<reqwest::Error>,
    StandardErrorResponse<CoreErrorResponseType>,
>;

#[derive(Debug, Error)]
pub enum OidcClientInitError {
    #[error("OIDC provider discovery failed: {0}")]
    Discovery(String),
}

pub(super) async fn discover_provider(
    issuer_url: IssuerUrl,
    http_client: &reqwest::Client,
) -> Result<CoreProviderMetadata, OidcClientInitError> {
    CoreProviderMetadata::discover_async(issuer_url, http_client)
        .await
        .map_err(|error| OidcClientInitError::Discovery(error.to_string()))
}

#[derive(Debug, Error)]
pub enum OidcClientError {
    #[error("Failed to start callback listener: {0}")]
    CallbackServer(#[source] CallbackListenError),
    #[error("Failed to set the redirect URI to the callback listener's assigned port")]
    CallbackRedirectPort,
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

/// OIDC Authorization Code + PKCE client for a native CLI client.
pub struct OidcClient<C = LocalCallbackServer, B = SystemBrowser> {
    oidc_client: ConfiguredCoreClient,
    scopes: Vec<Scope>,
    supported_scopes: Option<Vec<Scope>>,
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
        scopes: Vec<Scope>,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Result<Self, OidcClientInitError> {
        Self::with_components(
            issuer_url,
            client_id,
            scopes,
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
        scopes: Vec<Scope>,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Result<Self, OidcClientInitError> {
        Self::new(
            issuer_url,
            client_id,
            scopes,
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
        scopes: Vec<Scope>,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
    ) -> Result<Self, OidcClientInitError> {
        Self::with_components(
            issuer_url,
            client_id,
            scopes,
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
        scopes: Vec<Scope>,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
        browser: B,
    ) -> Result<Self, OidcClientInitError> {
        let provider = discover_provider(issuer_url, &http_client).await?;
        Ok(Self::from_provider_metadata(
            provider,
            client_id,
            scopes,
            redirect_url,
            http_client,
            callback_server,
            browser,
        ))
    }

    pub(super) fn from_provider_metadata(
        provider: CoreProviderMetadata,
        client_id: ClientId,
        scopes: Vec<Scope>,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
        browser: B,
    ) -> Self {
        let supported_scopes = provider.scopes_supported().cloned();
        let oidc_client = ConfiguredCoreClient::from_provider_metadata(provider, client_id, None);

        Self {
            oidc_client,
            scopes,
            supported_scopes,
            http_client,
            redirect_url,
            callback_server,
            browser,
        }
    }
}

#[async_trait]
impl<C: Send + Sync, B: Send + Sync> SupportedScopesProvider for OidcClient<C, B> {
    type Error = Infallible;

    async fn supported_scopes(&self) -> Result<Option<&[Scope]>, Self::Error> {
        Ok(self.supported_scopes.as_deref())
    }
}

#[async_trait]
impl<C, B> AuthorizationProvider for OidcClient<C, B>
where
    C: CallbackServer,
    B: Browser,
{
    type Error = OidcClientError;

    async fn authorize(&self) -> Result<Authorization, Self::Error> {
        let listener = self
            .callback_server
            .listen(self.redirect_url.url().path())
            .map_err(OidcClientError::CallbackServer)?;
        let redirect_url = if self.redirect_url.url().port() == Some(0) {
            let port = listener
                .local_addr()
                .map(|addr| addr.port())
                .filter(|&port| port != 0)
                .ok_or(OidcClientError::CallbackRedirectPort)?;
            let mut url = self.redirect_url.url().clone();
            url.set_port(Some(port))
                .map_err(|()| OidcClientError::CallbackRedirectPort)?;
            Cow::Owned(RedirectUrl::from_url(url))
        } else {
            Cow::Borrowed(&self.redirect_url)
        };

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorization_url, csrf_state, nonce) = self
            .oidc_client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // The OIDC library adds the openid scope automatically.
            .add_scopes(
                self.scopes
                    .iter()
                    .filter(|scope| scope.as_str() != "openid")
                    .cloned(),
            )
            .set_redirect_uri(Cow::Borrowed(redirect_url.as_ref()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        self.browser
            .open(&authorization_url)
            .map_err(OidcClientError::Browser)?;
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
            .set_redirect_uri(redirect_url)
            .set_pkce_verifier(pkce_verifier);

        let OwnedCoreTokenResponse {
            access_token,
            refresh_token,
            id_token,
            expires_in,
            ..
        } = token_request
            .request_async(&self.http_client)
            .await
            .map_err(OidcClientError::TokenEndpoint)?;

        if let Some(id_token) = id_token {
            id_token
                .claims(&self.oidc_client.id_token_verifier(), &nonce)
                .map_err(OidcClientError::IdTokenValidation)?;
        }

        Ok(Authorization::new(
            AccessToken::new(access_token.into_secret()),
            refresh_token.map(|token| RefreshToken::new(token.into_secret())),
            expires_in.map(Duration::from_secs),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::TokenProvider;
    use crate::oidc::tests::support::{
        BrowserMode, CallbackMode, error_test_server, invalid_id_token, mount_error_test_provider,
        mount_oidc_provider, successful_callback_components, test_client,
    };
    use wiremock::MockServer;

    #[tokio::test]
    async fn authorize_uses_assigned_port_for_authorization_and_token_exchange()
    -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount_oidc_provider(&server, 1, 1).await;

        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let redirect_url = RedirectUrl::new("http://127.0.0.1:0/oauth2/callback".to_owned())?;
        let bound_redirect_url =
            RedirectUrl::new("http://127.0.0.1:54321/oauth2/callback".to_owned())?;
        let scopes = "openid profile accounts:admin clients:admin";
        let (callback_server, browser) =
            successful_callback_components(&bound_redirect_url, scopes);
        let client = OidcClient::with_components(
            IssuerUrl::new(issuer)?,
            ClientId::new("razornd-identity-cli".to_owned()),
            scopes
                .split_whitespace()
                .map(|scope| Scope::new(scope.to_owned()))
                .collect(),
            redirect_url,
            http_client,
            callback_server,
            browser,
        )
        .await?;

        let authorization = client.authorize().await?;
        let requests = server.received_requests().await.unwrap();
        let token_request = requests
            .iter()
            .find(|request| request.url.path() == "/token")
            .unwrap();
        let params: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(&token_request.body).collect();
        assert_eq!(params["redirect_uri"], bound_redirect_url.url().as_str());
        assert_eq!(params["client_id"], "razornd-identity-cli");
        assert_eq!(params["grant_type"], "authorization_code");
        assert!(!params["code_verifier"].is_empty());
        assert!(!params.contains_key("client_secret"));
        assert!(
            !token_request
                .headers
                .contains_key(reqwest::header::AUTHORIZATION)
        );

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
        assert_eq!(authorization.expires_in(), Some(Duration::from_secs(3600)));

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

use crate::oidc::{
    AccessToken, CallbackServer, LocalCallbackServer, TokenProvider, TokenProviderError,
};
use async_trait::async_trait;
use openidconnect::{
    AuthorizationCode, ClientId, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use std::net::SocketAddr;

type ConfiguredCoreClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Configuration required to construct an [`OidcClient`].
pub struct OidcClientConfig {
    issuer_url: IssuerUrl,
    client_id: ClientId,
    redirect_url: RedirectUrl,
    callback_addr: SocketAddr,
}

impl OidcClientConfig {
    pub fn new(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
    ) -> Self {
        Self {
            issuer_url,
            client_id,
            redirect_url,
            callback_addr,
        }
    }
}

/// OIDC Authorization Code + PKCE token provider for a native CLI client.
///
/// This prototype performs an interactive login on every call. It does not
/// cache tokens or use refresh tokens; a store decorator can add that later.
pub struct OidcClient<C = LocalCallbackServer> {
    oidc_client: ConfiguredCoreClient,
    http_client: reqwest::Client,
    redirect_url: RedirectUrl,
    callback_server: C,
}

impl OidcClient<LocalCallbackServer> {
    /// Builds an OIDC client from its configuration.
    pub async fn new(
        config: OidcClientConfig,
        http_client: reqwest::Client,
    ) -> Result<Self, TokenProviderError> {
        let callback_server = LocalCallbackServer::new(config.callback_addr);
        Self::with_callback_server(config, http_client, callback_server).await
    }

    /// Builds an OIDC client from individual parameters.
    pub async fn from_params(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        callback_addr: SocketAddr,
        http_client: reqwest::Client,
    ) -> Result<Self, TokenProviderError> {
        Self::new(
            OidcClientConfig::new(issuer_url, client_id, redirect_url, callback_addr),
            http_client,
        )
        .await
    }
}

impl<C: CallbackServer> OidcClient<C> {
    /// Builds an OIDC client with a custom callback server.
    pub async fn with_callback_server(
        config: OidcClientConfig,
        http_client: reqwest::Client,
        callback_server: C,
    ) -> Result<Self, TokenProviderError> {
        let provider =
            CoreProviderMetadata::discover_async(config.issuer_url, &http_client).await?;

        let oidc_client = CoreClient::from_provider_metadata(provider, config.client_id, None)
            .set_redirect_uri(config.redirect_url.clone());

        Ok(Self {
            oidc_client,
            http_client,
            redirect_url: config.redirect_url,
            callback_server,
        })
    }

    async fn authorize(&self) -> Result<AccessToken, TokenProviderError> {
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

        let callback = self
            .callback_server
            .receive(&authorization_url, &self.redirect_url)
            .await?;

        if callback.state.as_deref() != Some(csrf_state.secret()) {
            return Err("OAuth state не совпадает".into());
        }
        if let Some(error) = callback.error {
            return Err(format!("Провайдер отклонил авторизацию: {error}").into());
        }

        let code = callback
            .code
            .ok_or("В callback отсутствует authorization code")?;
        let token_response = self
            .oidc_client
            .exchange_code(AuthorizationCode::new(code))?
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http_client)
            .await?;

        if let Some(id_token) = token_response.id_token() {
            id_token.claims(&self.oidc_client.id_token_verifier(), &nonce)?;
        }

        Ok(AccessToken::new(
            token_response.access_token().secret().to_owned(),
        ))
    }
}

#[async_trait]
impl<C: CallbackServer> TokenProvider for OidcClient<C> {
    async fn access_token(&self) -> Result<AccessToken, TokenProviderError> {
        self.authorize().await
    }
}

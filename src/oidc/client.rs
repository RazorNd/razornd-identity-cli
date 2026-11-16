use crate::oidc::{
    AccessToken, Browser, CallbackListener, CallbackServer, LocalCallbackServer, SystemBrowser,
    TokenProvider, TokenProviderError,
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
    ) -> Result<Self, TokenProviderError> {
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
    ) -> Result<Self, TokenProviderError> {
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
    ) -> Result<Self, TokenProviderError> {
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

impl<C: CallbackServer, B: Browser> OidcClient<C, B> {
    /// Builds an OIDC client with custom callback server and browser.
    pub async fn with_components(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        redirect_url: RedirectUrl,
        http_client: reqwest::Client,
        callback_server: C,
        browser: B,
    ) -> Result<Self, TokenProviderError> {
        let provider = CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;

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

        let listener = self.callback_server.listen(&self.redirect_url)?;
        self.browser.open(&authorization_url)?;
        println!("Ожидание ответа от провайдера на {} ...", self.redirect_url);
        let callback = listener.receive().await?;

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
impl<C: CallbackServer, B: Browser> TokenProvider for OidcClient<C, B> {
    async fn access_token(&self) -> Result<AccessToken, TokenProviderError> {
        self.authorize().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::tests::support::{mount_oidc_provider, successful_callback_components};
    use wiremock::MockServer;

    #[tokio::test]
    async fn access_token_returns_token_after_authorization_code_flow()
    -> Result<(), TokenProviderError> {
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
}

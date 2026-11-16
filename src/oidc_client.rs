use crate::token_provider::{AccessToken, TokenProvider, TokenProviderError};
use async_trait::async_trait;
use openidconnect::{
    AuthorizationCode, ClientId, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use std::{collections::HashMap, net::SocketAddr};

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
pub struct OidcClient {
    oidc_client: ConfiguredCoreClient,
    http_client: reqwest::Client,
    callback_addr: SocketAddr,
    redirect_url: RedirectUrl,
}

impl OidcClient {
    /// Builds an OIDC client from its configuration.
    pub async fn new(
        config: OidcClientConfig,
        http_client: reqwest::Client,
    ) -> Result<Self, TokenProviderError> {
        Self::from_params(
            config.issuer_url,
            config.client_id,
            config.redirect_url,
            config.callback_addr,
            http_client,
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
        let provider = CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;

        let oidc_client = CoreClient::from_provider_metadata(provider, client_id, None)
            .set_redirect_uri(redirect_url.clone());

        Ok(Self {
            oidc_client,
            http_client,
            callback_addr,
            redirect_url,
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

        let server = tiny_http::Server::http(self.callback_addr)?;
        webbrowser::open(authorization_url.as_str())?;
        println!("Ожидание ответа от провайдера на {} ...", self.redirect_url);

        let expected_path = self.redirect_url.url().path().to_owned();
        let mut callback = tokio::task::spawn_blocking(move || {
            let request = server.recv()?;
            let url = url::Url::parse(&format!("http://localhost{}", request.url()))?;
            if url.path() != expected_path {
                request.respond(tiny_http::Response::from_string("Not found"))?;
                return Err::<HashMap<String, String>, TokenProviderError>(
                    "Запрос пришёл на неожиданный callback path".into(),
                );
            }

            let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
            request.respond(tiny_http::Response::from_string(
                "Авторизация завершена. Можно закрыть это окно.",
            ))?;
            Ok(params)
        })
        .await??;

        if callback.get("state").map(String::as_str) != Some(csrf_state.secret()) {
            return Err("OAuth state не совпадает".into());
        }
        if let Some(error) = callback.get("error") {
            return Err(format!("Провайдер отклонил авторизацию: {error}").into());
        }

        let code = callback
            .remove("code")
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
impl TokenProvider for OidcClient {
    async fn access_token(&self) -> Result<AccessToken, TokenProviderError> {
        self.authorize().await
    }
}

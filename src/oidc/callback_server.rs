use crate::oidc::token_provider::TokenProviderError;
use async_trait::async_trait;
use openidconnect::{RedirectUrl, url::Url};
use std::{collections::HashMap, net::SocketAddr};

/// Authorization response received by the local callback server.
#[derive(Debug, Default)]
pub struct CallbackResponse {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Receives the browser's redirect after authorization.
#[async_trait]
pub trait CallbackServer: Send + Sync {
    /// Starts listening before opening the authorization URL, then waits for
    /// and parses the provider's redirect.
    async fn receive(
        &self,
        authorization_url: &Url,
        redirect_url: &RedirectUrl,
    ) -> Result<CallbackResponse, TokenProviderError>;
}

/// Local loopback HTTP callback listener for a native CLI.
pub struct LocalCallbackServer {
    callback_addr: SocketAddr,
}

impl LocalCallbackServer {
    pub fn new(callback_addr: SocketAddr) -> Self {
        Self { callback_addr }
    }
}

#[async_trait]
impl CallbackServer for LocalCallbackServer {
    async fn receive(
        &self,
        authorization_url: &Url,
        redirect_url: &RedirectUrl,
    ) -> Result<CallbackResponse, TokenProviderError> {
        let server = tiny_http::Server::http(self.callback_addr)?;
        webbrowser::open(authorization_url.as_str())?;
        println!("Ожидание ответа от провайдера на {redirect_url} ...");

        let expected_path = redirect_url.url().path().to_owned();
        let callback = tokio::task::spawn_blocking(move || {
            let request = server.recv()?;
            if request.method() != &tiny_http::Method::Get {
                request.respond(
                    tiny_http::Response::from_string("Method not allowed").with_status_code(405),
                )?;
                return Err::<CallbackResponse, TokenProviderError>(
                    "Ожидался GET запрос callback".into(),
                );
            }

            let url = Url::parse(&format!("http://localhost{}", request.url()))?;
            if url.path() != expected_path {
                request
                    .respond(tiny_http::Response::from_string("Not found").with_status_code(404))?;
                return Err::<CallbackResponse, TokenProviderError>(
                    "Запрос пришёл на неожиданный callback path".into(),
                );
            }

            let mut params = HashMap::new();
            for (key, value) in url.query_pairs() {
                if params
                    .insert(key.into_owned(), value.into_owned())
                    .is_some()
                {
                    request.respond(
                        tiny_http::Response::from_string("Duplicate query parameter")
                            .with_status_code(400),
                    )?;
                    return Err("Callback содержит повторяющийся query-параметр".into());
                }
            }

            request.respond(tiny_http::Response::from_string(
                "Авторизация завершена. Можно закрыть это окно.",
            ))?;

            Ok(CallbackResponse {
                code: params.remove("code"),
                state: params.remove("state"),
                error: params.remove("error"),
            })
        })
        .await??;

        Ok(callback)
    }
}

use crate::oidc::token_provider::TokenProviderError;
use async_trait::async_trait;
use openidconnect::{RedirectUrl, url::Url};
use std::{collections::HashMap, net::SocketAddr};

const CALLBACK_COMPLETE_HTML: &str = include_str!("callback_complete.html");

/// Authorization response received by the callback listener.
#[derive(Debug, Default)]
pub struct CallbackResponse {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Waits for a single authorization redirect.
#[async_trait]
pub trait CallbackListener: Send {
    async fn receive(self) -> Result<CallbackResponse, TokenProviderError>;
}

/// Binds a listener for the configured redirect URI.
pub trait CallbackServer: Send + Sync {
    type Listener: CallbackListener;

    fn listen(&self, redirect_url: &RedirectUrl) -> Result<Self::Listener, TokenProviderError>;
}

/// Local loopback HTTP callback server for a native CLI.
pub struct LocalCallbackServer {
    callback_addr: SocketAddr,
}

impl LocalCallbackServer {
    pub fn new(callback_addr: SocketAddr) -> Self {
        Self { callback_addr }
    }
}

pub struct LocalCallbackListener {
    server: tiny_http::Server,
    expected_path: String,
}

impl CallbackServer for LocalCallbackServer {
    type Listener = LocalCallbackListener;

    fn listen(&self, redirect_url: &RedirectUrl) -> Result<Self::Listener, TokenProviderError> {
        Ok(LocalCallbackListener {
            server: tiny_http::Server::http(self.callback_addr)?,
            expected_path: redirect_url.url().path().to_owned(),
        })
    }
}

#[async_trait]
impl CallbackListener for LocalCallbackListener {
    async fn receive(self) -> Result<CallbackResponse, TokenProviderError> {
        tokio::task::spawn_blocking(move || {
            let request = self.server.recv()?;
            if request.method() != &tiny_http::Method::Get {
                request.respond(
                    tiny_http::Response::from_string("Method not allowed").with_status_code(405),
                )?;
                return Err::<CallbackResponse, TokenProviderError>(
                    "Ожидался GET запрос callback".into(),
                );
            }

            let url = Url::parse(&format!("http://localhost{}", request.url()))?;
            if url.path() != self.expected_path {
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

            let content_type =
                tiny_http::Header::from_bytes("Content-Type", "text/html; charset=utf-8")
                    .expect("static Content-Type header is valid");
            request.respond(
                tiny_http::Response::from_string(CALLBACK_COMPLETE_HTML).with_header(content_type),
            )?;

            Ok(CallbackResponse {
                code: params.remove("code"),
                state: params.remove("state"),
                error: params.remove("error"),
            })
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[tokio::test]
    async fn local_callback_server_receives_browser_redirect() -> Result<(), TokenProviderError> {
        let probe = TcpListener::bind("127.0.0.1:0")?;
        let callback_addr = probe.local_addr()?;
        drop(probe);

        let redirect_url = RedirectUrl::new(format!("http://{callback_addr}/oauth2/callback"))?;
        let callback_server = LocalCallbackServer::new(callback_addr);
        let listener = callback_server.listen(&redirect_url)?;
        let callback_url = redirect_url.url().clone();
        let request = tokio::spawn(async move {
            let response = reqwest::Client::new()
                .get(callback_url)
                .query(&[("code", "test-authorization-code"), ("state", "test-state")])
                .send()
                .await?;
            let status = response.status();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = response.text().await?;
            Ok::<_, reqwest::Error>((status, content_type, body))
        });

        let callback = listener.receive().await?;
        let (status, content_type, body) = request.await??;

        assert_eq!(callback.code.as_deref(), Some("test-authorization-code"));
        assert_eq!(callback.state.as_deref(), Some("test-state"));
        assert_eq!(callback.error, None);
        assert_eq!(status, reqwest::StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("text/html; charset=utf-8"));
        assert!(body.contains("Вернитесь в CLI"));
        assert!(body.contains("data:image/svg+xml;base64,"));

        Ok(())
    }
}

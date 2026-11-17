use async_trait::async_trait;
use openidconnect::url::Url;
use std::{collections::HashMap, io, net::SocketAddr};
use thiserror::Error;

const CALLBACK_COMPLETE_HTML: &str = include_str!("callback_complete.html");

/// Failure to bind the local callback HTTP server.
#[derive(Debug, Error)]
#[error("failed to start callback listener: {0}")]
pub struct CallbackListenError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

/// Authorization response received by the callback listener.
#[derive(Debug, Default)]
pub struct CallbackResponse {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Error raised while receiving or parsing an authorization callback.
///
/// A failure to send an HTTP response is retained as secondary information and
/// does not replace the original callback error.
#[derive(Debug, Error)]
#[error("{kind}")]
pub struct CallbackReceiveError {
    #[source]
    kind: CallbackReceiveErrorKind,
    response_error: Option<io::Error>,
}

impl CallbackReceiveError {
    pub fn new(kind: CallbackReceiveErrorKind) -> Self {
        Self {
            kind,
            response_error: None,
        }
    }

    pub fn with_response_error(
        kind: CallbackReceiveErrorKind,
        response_error: Option<io::Error>,
    ) -> Self {
        Self {
            kind,
            response_error,
        }
    }

    pub fn kind(&self) -> &CallbackReceiveErrorKind {
        &self.kind
    }

    pub fn response_error(&self) -> Option<&io::Error> {
        self.response_error.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum CallbackReceiveErrorKind {
    #[error("failed to receive callback request: {0}")]
    ReceiveRequest(#[source] io::Error),
    #[error("invalid callback request: {0}")]
    InvalidRequest(&'static str),
    #[error("cannot parse callback query: repeated parameter `{0}`")]
    CannotParseQuery(String),
    #[error("failed to send callback response: {0}")]
    SendResponse(#[source] io::Error),
    #[error("callback request task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
    #[error("cannot parse callback URL: {0}")]
    ParseUrl(#[source] url::ParseError),
}

/// Waits for a single authorization redirect.
#[async_trait]
pub trait CallbackListener: Send {
    async fn receive(self) -> Result<CallbackResponse, CallbackReceiveError>;
}

/// Binds a listener for the configured redirect URI.
pub trait CallbackServer: Send + Sync {
    type Listener: CallbackListener;

    fn listen(
        &self,
        redirect_path: impl Into<String>,
    ) -> Result<Self::Listener, CallbackListenError>;
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

impl LocalCallbackListener {
    fn receive_blocking(self) -> Result<CallbackResponse, CallbackReceiveError> {
        let request = self.server.recv().map_err(|error| {
            CallbackReceiveError::new(CallbackReceiveErrorKind::ReceiveRequest(error))
        })?;
        self.handle_request(request)
    }

    fn handle_request(
        &self,
        request: tiny_http::Request,
    ) -> Result<CallbackResponse, CallbackReceiveError> {
        let (request, url) = self.validate_request(request)?;

        let callback = match parse_callback_query(&url) {
            Ok(callback) => callback,
            Err(kind) => {
                return Err(reject_request(request, kind, 400, "Invalid callback query"));
            }
        };

        send_completion_response(request)?;
        Ok(callback)
    }

    fn validate_request(
        &self,
        request: tiny_http::Request,
    ) -> Result<(tiny_http::Request, Url), CallbackReceiveError> {
        if request.method() != &tiny_http::Method::Get {
            return Err(reject_request(
                request,
                CallbackReceiveErrorKind::InvalidRequest("expected GET method"),
                405,
                "Method not allowed",
            ));
        }

        let url = parse_callback_url(request.url())?;
        if url.path() != self.expected_path {
            return Err(reject_request(
                request,
                CallbackReceiveErrorKind::InvalidRequest("unexpected callback path"),
                404,
                "Not found",
            ));
        }

        Ok((request, url))
    }
}

impl CallbackServer for LocalCallbackServer {
    type Listener = LocalCallbackListener;

    fn listen(
        &self,
        redirect_path: impl Into<String>,
    ) -> Result<Self::Listener, CallbackListenError> {
        Ok(LocalCallbackListener {
            server: tiny_http::Server::http(self.callback_addr).map_err(CallbackListenError)?,
            expected_path: redirect_path.into(),
        })
    }
}

#[async_trait]
impl CallbackListener for LocalCallbackListener {
    async fn receive(self) -> Result<CallbackResponse, CallbackReceiveError> {
        tokio::task::spawn_blocking(move || self.receive_blocking())
            .await
            .map_err(|error| CallbackReceiveError::new(CallbackReceiveErrorKind::Task(error)))?
    }
}

fn parse_callback_url(request_url: &str) -> Result<Url, CallbackReceiveError> {
    Url::parse(&format!("http://localhost{request_url}"))
        .map_err(|error| CallbackReceiveError::new(CallbackReceiveErrorKind::ParseUrl(error)))
}

fn parse_callback_query(url: &Url) -> Result<CallbackResponse, CallbackReceiveErrorKind> {
    let mut params = HashMap::new();
    for (key, value) in url.query_pairs() {
        if !matches!(key.as_ref(), "code" | "state" | "error") {
            continue;
        }
        let key = key.into_owned();
        if params.contains_key(&key) {
            return Err(CallbackReceiveErrorKind::CannotParseQuery(key));
        }
        params.insert(key, value.into_owned());
    }

    Ok(CallbackResponse {
        code: params.remove("code"),
        state: params.remove("state"),
        error: params.remove("error"),
    })
}

fn reject_request(
    request: tiny_http::Request,
    kind: CallbackReceiveErrorKind,
    status: u16,
    message: &str,
) -> CallbackReceiveError {
    let response_error = request
        .respond(tiny_http::Response::from_string(message).with_status_code(status))
        .err();
    CallbackReceiveError::with_response_error(kind, response_error)
}

fn send_completion_response(request: tiny_http::Request) -> Result<(), CallbackReceiveError> {
    let content_type = tiny_http::Header::from_bytes("Content-Type", "text/html; charset=utf-8")
        .expect("static Content-Type header is valid");
    request
        .respond(tiny_http::Response::from_string(CALLBACK_COMPLETE_HTML).with_header(content_type))
        .map_err(|error| CallbackReceiveError::new(CallbackReceiveErrorKind::SendResponse(error)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error::Error as _, net::TcpListener};

    #[test]
    fn listen_returns_typed_error_when_address_is_in_use() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = occupied.local_addr().unwrap();
        let result = LocalCallbackServer::new(address).listen("/callback");
        let error = result.err().expect("binding an occupied address must fail");

        assert!(error.source().is_some());
        let source = error.0.downcast_ref::<io::Error>().unwrap();
        assert_eq!(source.kind(), io::ErrorKind::AddrInUse);
    }

    async fn callback_request_error(
        method: reqwest::Method,
        request_path: &str,
    ) -> (CallbackReceiveError, reqwest::StatusCode) {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let callback_addr = probe.local_addr().unwrap();
        drop(probe);

        let listener = LocalCallbackServer::new(callback_addr)
            .listen("/oauth2/callback")
            .unwrap();
        let request_url = format!("http://{callback_addr}{request_path}");
        let request = tokio::spawn(async move {
            reqwest::Client::new()
                .request(method, request_url)
                .send()
                .await
                .unwrap()
                .status()
        });

        let error = listener.receive().await.unwrap_err();
        let status = request.await.unwrap();
        (error, status)
    }

    #[tokio::test]
    async fn local_callback_server_receives_browser_redirect() -> anyhow::Result<()> {
        let probe = TcpListener::bind("127.0.0.1:0")?;
        let callback_addr = probe.local_addr()?;
        drop(probe);

        let callback_server = LocalCallbackServer::new(callback_addr);
        let listener = callback_server.listen("/oauth2/callback")?;
        let request = tokio::spawn(async move {
            let response = reqwest::Client::new()
                .get(format!("http://{callback_addr}/oauth2/callback"))
                .query(&[
                    ("code", "test-authorization-code"),
                    ("state", "test-state"),
                    ("ignored", "one"),
                    ("ignored", "two"),
                ])
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

    #[tokio::test]
    async fn local_callback_listener_rejects_repeated_callback_parameters() {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let callback_addr = probe.local_addr().unwrap();
        drop(probe);

        let callback_server = LocalCallbackServer::new(callback_addr);
        let listener = callback_server.listen("/oauth2/callback").unwrap();

        let request = tokio::spawn(async move {
            reqwest::Client::new()
                .get(format!("http://{callback_addr}/oauth2/callback"))
                .query(&[
                    ("code", "first-code"),
                    ("code", "second-code"),
                    ("state", "test-state"),
                ])
                .send()
                .await
                .unwrap()
                .status()
        });

        let error = listener.receive().await.unwrap_err();
        let status = request.await.unwrap();

        assert!(matches!(
            error.kind(),
            CallbackReceiveErrorKind::CannotParseQuery(name) if name == "code"
        ));
        assert!(error.response_error().is_none());
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn local_callback_listener_returns_invalid_request_for_non_get_method() {
        let (error, status) =
            callback_request_error(reqwest::Method::POST, "/oauth2/callback").await;

        assert!(matches!(
            error.kind(),
            CallbackReceiveErrorKind::InvalidRequest("expected GET method")
        ));
        assert!(error.response_error().is_none());
        assert_eq!(status, reqwest::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn local_callback_listener_returns_invalid_request_for_wrong_path() {
        let (error, status) =
            callback_request_error(reqwest::Method::GET, "/unexpected-path").await;

        assert!(matches!(
            error.kind(),
            CallbackReceiveErrorKind::InvalidRequest("unexpected callback path")
        ));
        assert!(error.response_error().is_none());
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    }

    #[test]
    fn callback_receive_error_preserves_receive_request_error() {
        let error = CallbackReceiveError::new(CallbackReceiveErrorKind::ReceiveRequest(
            io::Error::other("receive failed"),
        ));

        assert!(matches!(
            error.kind(),
            CallbackReceiveErrorKind::ReceiveRequest(source) if source.to_string() == "receive failed"
        ));
        assert!(error.source().is_some());
        assert!(error.response_error().is_none());
    }

    #[test]
    fn callback_receive_error_preserves_send_response_error_as_primary_error() {
        let error = CallbackReceiveError::new(CallbackReceiveErrorKind::SendResponse(
            io::Error::other("response failed"),
        ));

        assert!(matches!(
            error.kind(),
            CallbackReceiveErrorKind::SendResponse(source) if source.to_string() == "response failed"
        ));
        assert!(error.source().is_some());
        assert!(error.response_error().is_none());
    }

    #[test]
    fn callback_receive_error_retains_response_error_without_replacing_primary_error() {
        let error = CallbackReceiveError::with_response_error(
            CallbackReceiveErrorKind::InvalidRequest("expected GET method"),
            Some(io::Error::other("response failed")),
        );

        assert!(matches!(
            error.kind(),
            CallbackReceiveErrorKind::InvalidRequest("expected GET method")
        ));
        assert_eq!(
            error.response_error().map(ToString::to_string).as_deref(),
            Some("response failed")
        );
    }

    #[test]
    fn callback_receive_error_preserves_parse_url_error() {
        let parse_error = Url::parse("http://[").unwrap_err();
        let error = CallbackReceiveError::new(CallbackReceiveErrorKind::ParseUrl(parse_error));

        assert!(matches!(
            error.kind(),
            CallbackReceiveErrorKind::ParseUrl(_)
        ));
        assert!(error.source().is_some());
    }
}

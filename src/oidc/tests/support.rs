use crate::oidc::{
    Browser, CallbackListenError, CallbackListener, CallbackReceiveError, CallbackReceiveErrorKind,
    CallbackResponse, CallbackServer, OidcClient, OidcClientInitError,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{ClientId, IssuerUrl, RedirectUrl};
use std::sync::{Arc, Mutex};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

pub(crate) struct SuccessfulCallbackServer {
    state: Arc<Mutex<Option<String>>>,
}

impl CallbackServer for SuccessfulCallbackServer {
    type Listener = SuccessfulCallbackListener;

    fn listen(
        &self,
        _redirect_path: impl Into<String>,
    ) -> Result<Self::Listener, CallbackListenError> {
        Ok(SuccessfulCallbackListener {
            state: self.state.clone(),
        })
    }
}

pub(crate) struct SuccessfulCallbackListener {
    state: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl CallbackListener for SuccessfulCallbackListener {
    async fn receive(self) -> Result<CallbackResponse, CallbackReceiveError> {
        let state = self
            .state
            .lock()
            .map_err(|_| {
                CallbackReceiveError::new(CallbackReceiveErrorKind::ReceiveRequest(
                    std::io::Error::other("callback state lock poisoned"),
                ))
            })?
            .take();
        Ok(CallbackResponse {
            code: Some("test-authorization-code".to_owned()),
            state,
            error: None,
        })
    }
}

pub(crate) struct SuccessfulBrowser {
    state: Arc<Mutex<Option<String>>>,
    redirect_uri: String,
}

impl Browser for SuccessfulBrowser {
    fn open(&self, authorization_url: &Url) -> Result<(), std::io::Error> {
        let params: std::collections::HashMap<_, _> =
            authorization_url.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some(self.redirect_uri.as_str())
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );

        *self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("callback state lock poisoned"))? =
            params.get("state").cloned();
        Ok(())
    }
}

pub(crate) fn successful_callback_components(
    redirect_url: &openidconnect::RedirectUrl,
) -> (SuccessfulCallbackServer, SuccessfulBrowser) {
    let state = Arc::new(Mutex::new(None));
    (
        SuccessfulCallbackServer {
            state: state.clone(),
        },
        SuccessfulBrowser {
            state,
            redirect_uri: redirect_url.url().as_str().to_owned(),
        },
    )
}

#[derive(Clone, Copy)]
pub(crate) enum CallbackMode {
    ListenError,
    ReceiveError,
    Success,
    InvalidState,
    ProviderRejected,
    MissingCode,
}

#[derive(Clone, Copy)]
pub(crate) enum BrowserMode {
    Success,
    Error,
}

pub(crate) struct TestCallbackServer {
    mode: CallbackMode,
    state: Arc<Mutex<Option<String>>>,
}

pub(crate) struct TestCallbackListener {
    mode: CallbackMode,
    state: Arc<Mutex<Option<String>>>,
}

impl CallbackServer for TestCallbackServer {
    type Listener = TestCallbackListener;

    fn listen(
        &self,
        _redirect_path: impl Into<String>,
    ) -> Result<Self::Listener, CallbackListenError> {
        if matches!(self.mode, CallbackMode::ListenError) {
            return Err(CallbackListenError(
                std::io::Error::other("test callback bind error").into(),
            ));
        }

        Ok(TestCallbackListener {
            mode: self.mode,
            state: self.state.clone(),
        })
    }
}

#[async_trait]
impl CallbackListener for TestCallbackListener {
    async fn receive(self) -> Result<CallbackResponse, CallbackReceiveError> {
        if matches!(self.mode, CallbackMode::ReceiveError) {
            return Err(CallbackReceiveError::new(
                CallbackReceiveErrorKind::ReceiveRequest(std::io::Error::other(
                    "test callback receive error",
                )),
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| {
                CallbackReceiveError::new(CallbackReceiveErrorKind::ReceiveRequest(
                    std::io::Error::other("test state lock poisoned"),
                ))
            })?
            .take();

        Ok(match self.mode {
            CallbackMode::InvalidState => CallbackResponse {
                code: Some("test-code".to_owned()),
                state: Some("incorrect-state".to_owned()),
                error: None,
            },
            CallbackMode::ProviderRejected => CallbackResponse {
                code: None,
                state,
                error: Some("access_denied".to_owned()),
            },
            CallbackMode::MissingCode => CallbackResponse {
                code: None,
                state,
                error: None,
            },
            _ => CallbackResponse {
                code: Some("test-authorization-code".to_owned()),
                state,
                error: None,
            },
        })
    }
}

pub(crate) struct TestBrowser {
    mode: BrowserMode,
    state: Arc<Mutex<Option<String>>>,
}

impl Browser for TestBrowser {
    fn open(&self, authorization_url: &Url) -> Result<(), std::io::Error> {
        if matches!(self.mode, BrowserMode::Error) {
            return Err(std::io::Error::other("test browser error"));
        }

        let state = authorization_url
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .ok_or_else(|| std::io::Error::other("authorization URL did not contain state"))?;
        *self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("test state lock poisoned"))? = Some(state);
        Ok(())
    }
}

pub(crate) async fn test_client(
    issuer: String,
    callback_mode: CallbackMode,
    browser_mode: BrowserMode,
) -> Result<OidcClient<TestCallbackServer, TestBrowser>, OidcClientInitError> {
    let redirect_url =
        RedirectUrl::new("http://127.0.0.1:54321/callback".to_owned()).expect("valid test URL");
    let state = Arc::new(Mutex::new(None));
    OidcClient::with_components(
        IssuerUrl::new(issuer).expect("valid test issuer URL"),
        ClientId::new("test-client".to_owned()),
        redirect_url,
        reqwest::Client::new(),
        TestCallbackServer {
            mode: callback_mode,
            state: state.clone(),
        },
        TestBrowser {
            mode: browser_mode,
            state,
        },
    )
    .await
}

pub(crate) async fn mount_oidc_provider(
    server: &MockServer,
    expected_discoveries: u64,
    expected_token_requests: u64,
) {
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["none"]
        })))
        .expect(expected_discoveries)
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": []
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(expected_token_requests)
        .mount(server)
        .await;
}

pub(crate) async fn error_test_server(
    include_token_endpoint: bool,
    token_status: u16,
    token_response: serde_json::Value,
) -> (MockServer, String) {
    let server = MockServer::start().await;
    let issuer = server.uri();
    mount_error_test_provider(
        &server,
        include_token_endpoint,
        token_status,
        token_response,
    )
    .await;
    (server, issuer)
}

pub(crate) async fn mount_error_test_provider(
    server: &MockServer,
    include_token_endpoint: bool,
    token_status: u16,
    token_response: serde_json::Value,
) {
    let issuer = server.uri();
    let mut metadata = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none"]
    });
    if include_token_endpoint {
        metadata["token_endpoint"] = serde_json::json!(format!("{issuer}/token"));
    }

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": []
        })))
        .mount(server)
        .await;
    if include_token_endpoint {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(token_status).set_body_json(token_response))
            .mount(server)
            .await;
    }
}

pub(crate) fn invalid_id_token(issuer: &str, audience: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"unknown"}"#);
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": "test-subject",
        "aud": audience,
        "exp": 4_102_444_800_u64,
        "iat": 1_700_000_000_u64,
        "nonce": "incorrect-nonce"
    });
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signature = URL_SAFE_NO_PAD.encode("not-a-valid-signature");
    format!("{header}.{payload}.{signature}")
}

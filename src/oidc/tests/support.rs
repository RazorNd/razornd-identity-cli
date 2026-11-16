use crate::oidc::{
    Browser, CallbackListener, CallbackResponse, CallbackServer, TokenProviderError,
};
use async_trait::async_trait;
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
        _redirect_url: &openidconnect::RedirectUrl,
    ) -> Result<Self::Listener, TokenProviderError> {
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
    async fn receive(self) -> Result<CallbackResponse, TokenProviderError> {
        let state = self
            .state
            .lock()
            .map_err(|_| "callback state lock poisoned")?
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
    fn open(&self, authorization_url: &Url) -> Result<(), TokenProviderError> {
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
            .map_err(|_| "callback state lock poisoned")? = params.get("state").cloned();
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
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(expected_token_requests)
        .mount(server)
        .await;
}

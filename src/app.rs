use crate::client::{IdentityClient, IdentityTokenProvider};
use openidconnect::{ClientId, IssuerUrl, RedirectUrl, Scope};
use razornd_identity_cli::RazorIdentityClient;
use razornd_identity_cli::oidc::{
    KeyringAuthorizationStorage, LazyOidcClient, StoredTokenProvider,
};
use url::Url;

const REDIRECT_URI: &str = "http://127.0.0.1:0/oauth2/callback";
const ISSUER_URI: &str = "https://auth.razornd.ru";
const DEFAULT_CLIENT_ID: &str = "razornd-identity-cli";
const DEFAULT_SCOPES: &str = "openid profile accounts:admin clients:admin";

pub(crate) struct IdentityApp {
    issuer_uri: &'static str,
    redirect_uri: &'static str,
    client_id: &'static str,
    scopes: Vec<&'static str>,
    http_client: reqwest::Client,
}

impl IdentityApp {
    pub(crate) fn configured() -> anyhow::Result<Self> {
        Ok(Self {
            issuer_uri: option_env!("RAZORND_IDENTITY_ISSUER_URI").unwrap_or(ISSUER_URI),
            redirect_uri: option_env!("RAZORND_IDENTITY_REDIRECT_URI").unwrap_or(REDIRECT_URI),
            client_id: option_env!("RAZORND_IDENTITY_CLIENT_ID").unwrap_or(DEFAULT_CLIENT_ID),
            scopes: option_env!("RAZORND_IDENTITY_SCOPES")
                .unwrap_or(DEFAULT_SCOPES)
                .split_whitespace()
                .collect(),
            http_client: Self::http_client()?,
        })
    }

    pub(crate) fn token_provider(&self) -> anyhow::Result<IdentityTokenProvider> {
        Ok(StoredTokenProvider::new(
            self.storage()?,
            self.authorizer()?,
        ))
    }

    pub(crate) fn client(&self) -> anyhow::Result<IdentityClient> {
        Ok(RazorIdentityClient::new(
            self.issuer_uri.parse()?,
            self.token_provider()?,
            self.http_client.clone(),
        ))
    }

    fn storage(&self) -> anyhow::Result<KeyringAuthorizationStorage> {
        // Use the original issuer string to keep existing keyring entries accessible.
        let keyring_account =
            serde_json::to_string(&(self.issuer_uri, self.client_id, &self.scopes))?;
        Ok(KeyringAuthorizationStorage::new(
            "razornd-identity-cli",
            keyring_account,
        ))
    }

    fn authorizer(&self) -> anyhow::Result<LazyOidcClient> {
        let redirect_url = self.redirect_uri.parse::<Url>()?;
        let callback_addr = redirect_url.authority().parse()?;
        let authorizer = LazyOidcClient::new(
            IssuerUrl::new(self.issuer_uri.to_owned())?,
            ClientId::new(self.client_id.to_owned()),
            self.scopes
                .iter()
                .map(|scope| Scope::new(scope.to_string()))
                .collect(),
            RedirectUrl::from_url(redirect_url),
            callback_addr,
            self.http_client.clone(),
        );
        Ok(authorizer)
    }

    fn http_client() -> Result<reqwest::Client, reqwest::Error> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
    }
}

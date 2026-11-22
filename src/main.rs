use openidconnect::{ClientId, IssuerUrl, RedirectUrl, Scope};
use razornd_identity_cli::RazorIdentityClient;
use razornd_identity_cli::oidc::{
    KeyringAuthorizationStorage, LazyOidcClient, StoredTokenProvider,
};
use url::Url;

mod cli;
mod client;

const REDIRECT_URI: &str = "http://127.0.0.1:0/oauth2/callback";
const ISSUER_URI: &str = "https://auth.razornd.ru";
const DEFAULT_CLIENT_ID: &str = "razornd-identity-cli";
const DEFAULT_SCOPES: &str = "openid profile accounts:admin clients:admin";

fn create_client() -> anyhow::Result<client::IdentityClient> {
    let issuer_uri = option_env!("RAZORND_IDENTITY_ISSUER_URI")
        .unwrap_or(ISSUER_URI)
        .to_owned();
    let redirect_url = option_env!("RAZORND_IDENTITY_REDIRECT_URI")
        .unwrap_or(REDIRECT_URI)
        .parse::<Url>()?;
    let client_id = option_env!("RAZORND_IDENTITY_CLIENT_ID").unwrap_or(DEFAULT_CLIENT_ID);
    let scopes = option_env!("RAZORND_IDENTITY_SCOPES")
        .unwrap_or(DEFAULT_SCOPES)
        .split_whitespace()
        .collect::<Vec<_>>();

    let issuer_url = IssuerUrl::new(issuer_uri)?;
    let base_url = issuer_url.url().clone();
    let keyring_account = serde_json::to_string(&(issuer_url.as_str(), client_id, &scopes))?;

    // Reuse this client (or its cheap clone) for OidcClient and IdentityClient.
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let authorizer = LazyOidcClient::new(
        issuer_url,
        ClientId::new(client_id.to_owned()),
        scopes
            .into_iter()
            .map(|scope| Scope::new(scope.to_owned()))
            .collect(),
        RedirectUrl::from_url(redirect_url.clone()),
        redirect_url.authority().parse()?,
        http_client.clone(),
    );
    let storage = KeyringAuthorizationStorage::new("razornd-identity-cli", keyring_account);
    let token_provider = StoredTokenProvider::new(storage, authorizer);

    Ok(RazorIdentityClient::new(
        base_url,
        token_provider,
        http_client,
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run(create_client()?).await
}

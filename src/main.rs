use anyhow::Result;
use openidconnect::{ClientId, IssuerUrl, RedirectUrl};
use razornd_identity_cli::oidc::{
    KeyringAuthorizationStorage, LazyOidcClient, StoredTokenProvider, TokenProvider,
};

const REDIRECT_URI: &str = "http://127.0.0.1:53780/oauth2/callback";

#[tokio::main]
async fn main() -> Result<()> {
    // Reuse this client (or its cheap clone) for OidcClient and IdentityClient.
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let authorizer = LazyOidcClient::new(
        IssuerUrl::new("http://localhost:8080".to_owned())?,
        ClientId::new("http-client".to_owned()),
        RedirectUrl::new(REDIRECT_URI.to_owned())?,
        "127.0.0.1:53780".parse()?,
        http_client.clone(),
    );
    let storage = KeyringAuthorizationStorage::new("razornd-identity-cli", "default");
    let token_provider = StoredTokenProvider::new(storage, authorizer);

    let access_token = token_provider.access_token().await?;
    println!("Access token получен: {access_token:?}");
    Ok(())
}

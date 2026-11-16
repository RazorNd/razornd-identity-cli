use openidconnect::{ClientId, IssuerUrl, RedirectUrl};
use razornd_identity_cli::lazy_oidc_client::LazyOidcClient;
use razornd_identity_cli::token_provider::{TokenProvider, TokenProviderError};

const REDIRECT_URI: &str = "http://127.0.0.1:53780/oauth2/callback";

#[tokio::main]
async fn main() -> Result<(), TokenProviderError> {
    // Reuse this client (or its cheap clone) for OidcClient and IdentityClient.
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let token_provider = LazyOidcClient::new(
        IssuerUrl::new("http://localhost:8080".to_owned())?,
        ClientId::new("http-client".to_owned()),
        RedirectUrl::new(REDIRECT_URI.to_owned())?,
        "127.0.0.1:53780".parse()?,
        http_client.clone(),
    );

    let access_token = token_provider.access_token().await?;
    println!("Access token получен: {access_token:?}");
    Ok(())
}

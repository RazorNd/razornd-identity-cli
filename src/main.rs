use anyhow::Result;
use openidconnect::{ClientId, IssuerUrl, RedirectUrl};
use razornd_identity_cli::RazorIdentityClient;
use razornd_identity_cli::oidc::{
    KeyringAuthorizationStorage, KeyringAuthorizationStorageError, LazyOidcClient,
    LazyOidcClientError, StoredTokenProvider, StoredTokenProviderError,
};
use url::Url;

const REDIRECT_URI: &str = "http://127.0.0.1:53780/oauth2/callback";

type IdentityClient = RazorIdentityClient<
    StoredTokenProvider<KeyringAuthorizationStorage, LazyOidcClient, LazyOidcClientError>,
    StoredTokenProviderError<LazyOidcClientError, KeyringAuthorizationStorageError>,
>;

#[tokio::main]
async fn main() -> Result<()> {
    let client = create_client()?;

    println!("{:?}", client.get_account("test").await?);
    Ok(())
}

fn create_client() -> Result<IdentityClient> {
    let issuer_url = IssuerUrl::new("http://localhost:8080".to_owned())?;
    let base_url = issuer_url.url().clone();

    // Reuse this client (or its cheap clone) for OidcClient and IdentityClient.
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let redirect_url = REDIRECT_URI.parse::<Url>()?;
    let authorizer = LazyOidcClient::new(
        issuer_url,
        ClientId::new("http-client".to_owned()),
        RedirectUrl::from_url(redirect_url.clone()),
        redirect_url.authority().parse()?,
        http_client.clone(),
    );
    let storage = KeyringAuthorizationStorage::new("razornd-identity-cli", "default");
    let token_provider = StoredTokenProvider::new(storage, authorizer);

    let client = RazorIdentityClient::new(base_url, token_provider, http_client);
    Ok(client)
}

use super::{RazorIdentityClient, RazorIdentityClientError};
use crate::oidc::TokenProvider;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};
use url::Url;

#[cfg(test)]
mod tests;

macro_rules! wire_enum {
    ($(#[$attr:meta])* pub enum $name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        $(#[$attr])*
        #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
        pub enum $name {
            $(#[serde(rename = $value)] $variant),+
        }

        impl $name {
            pub const VALUES: &'static [Self] = &[$(Self::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

wire_enum! {
    /// Client authentication method as represented by the identity service.
    pub enum ClientAuthenticationMethod {
        None => "none",
        ClientSecretBasic => "client_secret_basic",
        ClientSecretPost => "client_secret_post",
        ClientSecretJwt => "client_secret_jwt",
        PrivateKeyJwt => "private_key_jwt",
        TlsClientAuth => "tls_client_auth",
        SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
    }
}

wire_enum! {
    /// OAuth2 grant type as represented by the identity service.
    pub enum ClientGrantType {
        AuthorizationCode => "authorization_code",
        ClientCredentials => "client_credentials",
        RefreshToken => "refresh_token",
        DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
        JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
        TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
    }
}

wire_enum! {
    /// Format used for issued access tokens.
    pub enum ClientAccessTokenFormat {
        SelfContained => "self-contained",
        Reference => "reference",
    }
}

/// Token settings returned by the API. Lifetimes are ISO 8601 duration strings.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientTokenSettings {
    pub authorization_code_time_to_live: String,
    pub access_token_time_to_live: String,
    pub access_token_format: ClientAccessTokenFormat,
    pub reuse_refresh_tokens: bool,
    pub refresh_token_time_to_live: String,
}

/// Optional overrides for creating or updating a client's token settings.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientTokenSettingsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code_time_to_live: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_time_to_live: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_format: Option<ClientAccessTokenFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reuse_refresh_tokens: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_time_to_live: Option<String>,
}

impl ClientTokenSettingsRequest {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Public metadata of an API-managed OAuth2 client.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OAuthClient {
    pub client_id: String,
    pub client_name: String,
    pub client_authentication_methods: BTreeSet<ClientAuthenticationMethod>,
    pub authorization_grant_types: BTreeSet<ClientGrantType>,
    pub redirect_uris: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub token_settings: ClientTokenSettings,
}

/// Creation response. The service returns a secret only for non-public clients.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedClient {
    #[serde(flatten)]
    pub details: OAuthClient,
    pub client_secret: Option<String>,
}

impl fmt::Debug for CreatedClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedClient")
            .field("details", &self.details)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Client registration request. The service supplies the client ID and any secret.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreateClientRequest {
    pub client_name: String,
    pub client_authentication_methods: BTreeSet<ClientAuthenticationMethod>,
    pub authorization_grant_types: BTreeSet<ClientGrantType>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub redirect_uris: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub scopes: BTreeSet<String>,
    #[serde(skip_serializing_if = "ClientTokenSettingsRequest::is_empty")]
    pub token_settings: ClientTokenSettingsRequest,
}

/// Add/remove operations for one metadata set, not a replacement for the set.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SetChanges<T> {
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub add: BTreeSet<T>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub remove: BTreeSet<T>,
}

impl<T> Default for SetChanges<T> {
    fn default() -> Self {
        Self {
            add: BTreeSet::new(),
            remove: BTreeSet::new(),
        }
    }
}

impl<T> SetChanges<T> {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }
}

/// Partial update of an API-managed OAuth2 client.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateClientRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "SetChanges::is_empty")]
    pub client_authentication_methods: SetChanges<ClientAuthenticationMethod>,
    #[serde(skip_serializing_if = "SetChanges::is_empty")]
    pub authorization_grant_types: SetChanges<ClientGrantType>,
    #[serde(skip_serializing_if = "SetChanges::is_empty")]
    pub redirect_uris: SetChanges<String>,
    #[serde(skip_serializing_if = "SetChanges::is_empty")]
    pub scopes: SetChanges<String>,
    #[serde(skip_serializing_if = "ClientTokenSettingsRequest::is_empty")]
    pub token_settings: ClientTokenSettingsRequest,
}

impl UpdateClientRequest {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl<P: TokenProvider> RazorIdentityClient<P> {
    /// Registers an OAuth2 client, returning its generated secret if present.
    pub async fn create_client(
        &self,
        request: &CreateClientRequest,
    ) -> Result<CreatedClient, RazorIdentityClientError<P::Error>> {
        let response = self
            .authorized_request(Method::POST, self.clients_url()?)
            .await?
            .json(request)
            .send()
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Err(RazorIdentityClientError::ClientAlreadyExists);
        }
        let response = self.expect_status(response, StatusCode::CREATED).await?;
        Ok(response.json().await?)
    }

    /// Gets a client by its public client ID, or returns `None` if not found.
    pub async fn get_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, RazorIdentityClientError<P::Error>> {
        let response = self
            .authorized_request(Method::GET, self.client_url(client_id)?)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = self.expect_status(response, StatusCode::OK).await?;
        Ok(Some(response.json().await?))
    }

    /// Applies a partial update, or returns `None` if the client was not found.
    pub async fn update_client(
        &self,
        client_id: &str,
        request: &UpdateClientRequest,
    ) -> Result<Option<OAuthClient>, RazorIdentityClientError<P::Error>> {
        let response = self
            .authorized_request(Method::PATCH, self.client_url(client_id)?)
            .await?
            .json(request)
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = self.expect_status(response, StatusCode::OK).await?;
        Ok(Some(response.json().await?))
    }

    /// Removes an OAuth2 client. Returns `false` if the client was not found.
    pub async fn delete_client(
        &self,
        client_id: &str,
    ) -> Result<bool, RazorIdentityClientError<P::Error>> {
        let response = self
            .authorized_request(Method::DELETE, self.client_url(client_id)?)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        self.expect_status(response, StatusCode::NO_CONTENT).await?;
        Ok(true)
    }

    fn clients_url(&self) -> Result<Url, RazorIdentityClientError<P::Error>> {
        Ok(self.base_url.join("api/admin/clients")?)
    }

    fn client_url(&self, client_id: &str) -> Result<Url, RazorIdentityClientError<P::Error>> {
        if matches!(client_id.trim(), "" | "." | "..") {
            return Err(RazorIdentityClientError::InvalidClientId);
        }
        let mut url = self.clients_url()?;
        url.path_segments_mut()
            .expect("HTTP(S) service URLs support path segments")
            .push(client_id);
        Ok(url)
    }
}

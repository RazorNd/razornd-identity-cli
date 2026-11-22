use crate::oidc::{AccessToken, AuthorizationStorage, StoredAuthorization};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, UNIX_EPOCH};
use thiserror::Error;

/// Persists authorization data as a secret in the platform keyring.
///
/// The keyring entry is identified by `service` and `username`.
pub struct KeyringAuthorizationStorage {
    service: String,
    username: String,
}

impl KeyringAuthorizationStorage {
    pub fn new(service: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            username: username.into(),
        }
    }

    fn clear_entry(entry: &keyring::Entry) -> Result<(), KeyringAuthorizationStorageError> {
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, KeyringAuthorizationStorageError> {
        Ok(keyring::Entry::new(&self.service, &self.username)?)
    }
}

#[derive(Debug, Error)]
pub enum KeyringAuthorizationStorageError {
    #[error("keyring operation failed: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("failed to serialize authorization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("stored authorization expiration is invalid")]
    InvalidExpiration,
}

#[derive(Deserialize, Serialize)]
struct PersistedAuthorization {
    access_token: String,
    expires_at_seconds: u64,
    expires_at_nanoseconds: u32,
}

impl TryFrom<StoredAuthorization> for PersistedAuthorization {
    type Error = KeyringAuthorizationStorageError;

    fn try_from(authorization: StoredAuthorization) -> Result<Self, Self::Error> {
        let expiration = authorization
            .expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyringAuthorizationStorageError::InvalidExpiration)?;

        Ok(Self {
            access_token: authorization.access_token.into_secret(),
            expires_at_seconds: expiration.as_secs(),
            expires_at_nanoseconds: expiration.subsec_nanos(),
        })
    }
}

impl TryFrom<PersistedAuthorization> for StoredAuthorization {
    type Error = KeyringAuthorizationStorageError;

    fn try_from(authorization: PersistedAuthorization) -> Result<Self, Self::Error> {
        if authorization.expires_at_nanoseconds >= 1_000_000_000 {
            return Err(KeyringAuthorizationStorageError::InvalidExpiration);
        }

        let expiration = Duration::new(
            authorization.expires_at_seconds,
            authorization.expires_at_nanoseconds,
        );
        let expires_at = UNIX_EPOCH
            .checked_add(expiration)
            .ok_or(KeyringAuthorizationStorageError::InvalidExpiration)?;

        Ok(StoredAuthorization {
            access_token: AccessToken::new(authorization.access_token),
            expires_at,
        })
    }
}

#[async_trait]
impl AuthorizationStorage for KeyringAuthorizationStorage {
    type Error = KeyringAuthorizationStorageError;

    async fn load(&self) -> Result<Option<StoredAuthorization>, Self::Error> {
        let entry = self.entry()?;
        let secret = match entry.get_password() {
            Ok(secret) => secret,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        let authorization: PersistedAuthorization = serde_json::from_str(&secret)?;
        Ok(Some(StoredAuthorization::try_from(authorization)?))
    }

    async fn save(&self, authorization: StoredAuthorization) -> Result<(), Self::Error> {
        let entry = self.entry()?;
        let persisted = PersistedAuthorization::try_from(authorization)?;
        entry.set_password(&serde_json::to_string(&persisted)?)?;
        Ok(())
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        Self::clear_entry(&self.entry()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::{api::CredentialStoreApi, mock};

    fn mock_entry() -> keyring::Entry {
        keyring::Entry {
            inner: mock::Store::new()
                .unwrap()
                .build("test-service", "test-account", None)
                .unwrap(),
        }
    }

    #[test]
    fn clear_deletes_the_entry_and_succeeds_when_called_again() {
        let entry = mock_entry();
        entry.set_password("not valid authorization JSON").unwrap();

        KeyringAuthorizationStorage::clear_entry(&entry).unwrap();
        assert!(matches!(entry.get_password(), Err(keyring::Error::NoEntry)));
        KeyringAuthorizationStorage::clear_entry(&entry).unwrap();
    }

    #[test]
    fn clear_propagates_keyring_errors() {
        let entry = mock_entry();
        let credential = entry.inner.as_any().downcast_ref::<mock::Cred>().unwrap();
        credential.set_error(keyring::Error::NoDefaultStore);

        assert!(matches!(
            KeyringAuthorizationStorage::clear_entry(&entry),
            Err(KeyringAuthorizationStorageError::Keyring(
                keyring::Error::NoDefaultStore
            ))
        ));
    }

    #[test]
    fn persisted_authorization_round_trips_token_and_expiration() {
        let expires_at = UNIX_EPOCH + Duration::new(1_800_000_000, 123_456_789);
        let authorization =
            StoredAuthorization::new(AccessToken::new("test-access-token".to_owned()), expires_at);

        let persisted = PersistedAuthorization::try_from(authorization).unwrap();
        let json = serde_json::to_string(&persisted).unwrap();
        let parsed: PersistedAuthorization = serde_json::from_str(&json).unwrap();
        let restored = StoredAuthorization::try_from(parsed).unwrap();

        assert_eq!(restored.access_token.expose_secret(), "test-access-token");
        assert_eq!(restored.expires_at, expires_at);
    }
}

use super::{AuthorizationStorage, StoredAuthorization};
use crate::oidc::{AccessToken, Authorization, AuthorizationProvider, TokenProvider};
use async_trait::async_trait;
use std::time::SystemTime;
use thiserror::Error as ThisError;
use tokio::sync::Mutex;

/// Refreshes expired authorizations and stores successful results.
///
/// The mutex makes concurrent requests through the same provider share a
/// single re-authorization and prevents clearing storage during that operation.
pub struct StoredTokenProvider<S, A> {
    storage: S,
    authorizer: A,
    authorization_lock: Mutex<()>,
}

impl<S, A> StoredTokenProvider<S, A> {
    pub fn new(storage: S, authorizer: A) -> Self {
        Self {
            storage,
            authorizer,
            authorization_lock: Mutex::new(()),
        }
    }
}

impl<S: AuthorizationStorage, A> StoredTokenProvider<S, A> {
    /// Removes the local authorization without contacting the provider.
    pub async fn clear_authorization(&self) -> Result<(), S::Error> {
        let _guard = self.authorization_lock.lock().await;
        self.storage.clear().await
    }
}

#[derive(Debug, ThisError)]
pub enum StoredTokenProviderError<AuthorizationError, StorageError> {
    #[error("authorization failed: {0}")]
    Authorization(#[source] AuthorizationError),
    #[error("authorization storage failed: {0}")]
    Storage(#[source] StorageError),
    #[error("cannot save authorization: the access token has no usable expiration time")]
    InvalidExpiration,
}

impl<S, A> StoredTokenProvider<S, A>
where
    S: AuthorizationStorage,
    A: AuthorizationProvider,
{
    /// Runs a fresh authorization and replaces the cached token after success.
    pub async fn reauthorize(&self) -> Result<(), StoredTokenProviderError<A::Error, S::Error>> {
        let _guard = self.authorization_lock.lock().await;
        let authorization = self.authorize().await?;
        let stored = stored_authorization(&authorization)
            .filter(|stored| !stored.is_expired())
            .ok_or(StoredTokenProviderError::InvalidExpiration)?;
        self.save_authorization(stored).await
    }

    async fn authorize(
        &self,
    ) -> Result<Authorization, StoredTokenProviderError<A::Error, S::Error>> {
        self.authorizer
            .authorize()
            .await
            .map_err(StoredTokenProviderError::Authorization)
    }

    async fn save_authorization(
        &self,
        authorization: StoredAuthorization,
    ) -> Result<(), StoredTokenProviderError<A::Error, S::Error>> {
        self.storage
            .save(authorization)
            .await
            .map_err(StoredTokenProviderError::Storage)
    }
}

#[async_trait]
impl<S, A> TokenProvider for StoredTokenProvider<S, A>
where
    S: AuthorizationStorage,
    A: AuthorizationProvider,
{
    type Error = StoredTokenProviderError<A::Error, S::Error>;

    async fn access_token(&self) -> Result<AccessToken, Self::Error> {
        let _guard = self.authorization_lock.lock().await;

        if let Some(stored) = self
            .storage
            .load()
            .await
            .map_err(StoredTokenProviderError::Storage)?
            && !stored.is_expired()
        {
            return Ok(stored.into_access_token());
        }

        let authorization = self.authorize().await?;
        if let Some(stored) = stored_authorization(&authorization) {
            self.save_authorization(stored).await?;
        }

        let (access_token, _, _) = authorization.into_parts();

        Ok(access_token)
    }
}

fn stored_authorization(authorization: &Authorization) -> Option<StoredAuthorization> {
    let expires_at = SystemTime::now().checked_add(authorization.expires_in()?)?;
    Some(StoredAuthorization::new(
        authorization.access_token().clone(),
        expires_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::{InMemoryAuthorizationStorage, RefreshToken, TokenProvider};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    struct CountingAuthorizer {
        calls: AtomicUsize,
        expires_in: Option<Duration>,
    }

    struct RejectingAuthorizer;

    #[async_trait]
    impl AuthorizationProvider for RejectingAuthorizer {
        type Error = std::io::Error;

        async fn authorize(&self) -> Result<Authorization, Self::Error> {
            Err(std::io::Error::other("authorization declined"))
        }
    }

    #[async_trait]
    impl AuthorizationProvider for CountingAuthorizer {
        type Error = std::convert::Infallible;

        async fn authorize(&self) -> Result<Authorization, Self::Error> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Authorization::new(
                AccessToken::new(format!("access-token-{call}")),
                Some(RefreshToken::new(format!("refresh-token-{call}"))),
                self.expires_in,
            ))
        }
    }

    #[tokio::test]
    async fn reuses_unexpired_authorization_from_storage() {
        let authorizer = CountingAuthorizer {
            calls: AtomicUsize::new(0),
            expires_in: Some(Duration::from_secs(3600)),
        };
        let provider =
            StoredTokenProvider::new(InMemoryAuthorizationStorage::default(), authorizer);

        for _ in 0..2 {
            let token = provider.access_token().await.unwrap();
            assert_eq!(token.expose_secret(), "access-token-0");
        }
    }

    #[tokio::test]
    async fn clear_authorization_removes_cached_token_without_reauthorizing() {
        let storage = InMemoryAuthorizationStorage::default();
        let provider = StoredTokenProvider::new(
            storage.clone(),
            CountingAuthorizer {
                calls: AtomicUsize::new(0),
                expires_in: Some(Duration::from_secs(3600)),
            },
        );
        assert_eq!(
            provider.access_token().await.unwrap().expose_secret(),
            "access-token-0"
        );

        provider.clear_authorization().await.unwrap();
        provider.clear_authorization().await.unwrap();
        assert!(storage.load().await.unwrap().is_none());
        assert_eq!(provider.authorizer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            provider.access_token().await.unwrap().expose_secret(),
            "access-token-1"
        );
    }

    async fn storage_with_cached_authorization() -> InMemoryAuthorizationStorage {
        let storage = InMemoryAuthorizationStorage::default();
        storage
            .save(StoredAuthorization::new(
                AccessToken::new("cached-token".to_owned()),
                SystemTime::now() + Duration::from_secs(3600),
            ))
            .await
            .unwrap();
        storage
    }

    #[tokio::test]
    async fn reauthorize_replaces_an_unexpired_cached_token() {
        let provider = StoredTokenProvider::new(
            storage_with_cached_authorization().await,
            CountingAuthorizer {
                calls: AtomicUsize::new(0),
                expires_in: Some(Duration::from_secs(3600)),
            },
        );

        provider.reauthorize().await.unwrap();
        assert_eq!(
            provider.access_token().await.unwrap().expose_secret(),
            "access-token-0"
        );
    }

    #[tokio::test]
    async fn failed_reauthorization_leaves_the_cached_token_unchanged() {
        let provider = StoredTokenProvider::new(
            storage_with_cached_authorization().await,
            RejectingAuthorizer,
        );

        assert!(matches!(
            provider.reauthorize().await,
            Err(StoredTokenProviderError::Authorization(_))
        ));
        assert_eq!(
            provider.access_token().await.unwrap().expose_secret(),
            "cached-token"
        );
    }

    #[tokio::test]
    async fn reauthorize_rejects_unusable_expiration_without_replacing_cached_token() {
        for expires_in in [None, Some(Duration::ZERO), Some(Duration::MAX)] {
            let provider = StoredTokenProvider::new(
                storage_with_cached_authorization().await,
                CountingAuthorizer {
                    calls: AtomicUsize::new(0),
                    expires_in,
                },
            );

            assert!(matches!(
                provider.reauthorize().await,
                Err(StoredTokenProviderError::InvalidExpiration)
            ));
            assert_eq!(
                provider.access_token().await.unwrap().expose_secret(),
                "cached-token"
            );
        }
    }

    #[tokio::test]
    async fn authorizes_again_when_stored_token_has_expired() {
        let authorizer = CountingAuthorizer {
            calls: AtomicUsize::new(0),
            expires_in: Some(Duration::ZERO),
        };
        let provider =
            StoredTokenProvider::new(InMemoryAuthorizationStorage::default(), authorizer);

        for call in 0..2 {
            let token = provider.access_token().await.unwrap();
            assert_eq!(token.expose_secret(), format!("access-token-{call}"));
        }
    }

    #[tokio::test]
    async fn stored_authorization_maps_lifetime_to_absolute_expiration() {
        let stored = stored_authorization(&Authorization::new(
            AccessToken::new("access-token".to_owned()),
            None,
            Some(Duration::from_secs(60)),
        ))
        .unwrap();

        assert!(!stored.is_expired());
    }

    #[tokio::test]
    async fn does_not_store_authorization_without_expiration() {
        let authorizer = CountingAuthorizer {
            calls: AtomicUsize::new(0),
            expires_in: None,
        };
        let storage = InMemoryAuthorizationStorage::default();
        let provider = StoredTokenProvider::new(storage.clone(), authorizer);

        for call in 0..2 {
            let token = provider.access_token().await.unwrap();
            assert_eq!(token.expose_secret(), format!("access-token-{call}"));
        }

        assert!(storage.load().await.unwrap().is_none());
    }
}

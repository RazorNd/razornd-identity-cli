use super::{AuthorizationStorage, StoredAuthorization};
use crate::oidc::{AccessToken, Authorization, AuthorizationProvider, TokenProvider};
use async_trait::async_trait;
use std::{error::Error, marker::PhantomData, time::SystemTime};
use thiserror::Error as ThisError;
use tokio::sync::Mutex;

/// Refreshes expired authorizations and stores successful results.
///
/// The mutex makes concurrent requests through the same provider share a
/// single re-authorization and prevents clearing storage during that operation.
pub struct StoredTokenProvider<S, A, E> {
    storage: S,
    authorizer: A,
    authorization_lock: Mutex<()>,
    error: PhantomData<fn() -> E>,
}

impl<S, A, E> StoredTokenProvider<S, A, E> {
    pub fn new(storage: S, authorizer: A) -> Self {
        Self {
            storage,
            authorizer,
            authorization_lock: Mutex::new(()),
            error: PhantomData,
        }
    }
}

impl<S: AuthorizationStorage, A, E> StoredTokenProvider<S, A, E> {
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
}

#[async_trait]
impl<S, A, E> TokenProvider<StoredTokenProviderError<E, S::Error>> for StoredTokenProvider<S, A, E>
where
    S: AuthorizationStorage,
    A: AuthorizationProvider<E>,
    E: Error + Send + Sync + 'static,
{
    async fn access_token(&self) -> Result<AccessToken, StoredTokenProviderError<E, S::Error>> {
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

        let authorization = self
            .authorizer
            .authorize()
            .await
            .map_err(StoredTokenProviderError::Authorization)?;
        let access_token = authorization.access_token().clone();
        if let Some(stored) = stored_authorization(authorization) {
            self.storage
                .save(stored)
                .await
                .map_err(StoredTokenProviderError::Storage)?;
        }

        Ok(access_token)
    }
}

fn stored_authorization(authorization: Authorization) -> Option<StoredAuthorization> {
    let (access_token, _refresh_token, expires_in) = authorization.into_parts();
    let expires_at = SystemTime::now().checked_add(expires_in?)?;
    Some(StoredAuthorization::new(access_token, expires_at))
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

    #[async_trait]
    impl AuthorizationProvider<std::convert::Infallible> for CountingAuthorizer {
        async fn authorize(&self) -> Result<Authorization, std::convert::Infallible> {
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
        let stored = stored_authorization(Authorization::new(
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

use crate::oidc::AccessToken;
use async_trait::async_trait;
use std::{error::Error, sync::Arc, time::SystemTime};
use tokio::sync::Mutex;

/// An access token together with its absolute expiration time.
#[derive(Clone)]
pub struct StoredAuthorization {
    access_token: AccessToken,
    expires_at: SystemTime,
}

impl StoredAuthorization {
    pub fn new(access_token: AccessToken, expires_at: SystemTime) -> Self {
        Self {
            access_token,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at <= SystemTime::now()
    }

    pub fn into_access_token(self) -> AccessToken {
        self.access_token
    }
}

/// Persists the current authorization.
#[async_trait]
pub trait AuthorizationStorage: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    async fn load(&self) -> Result<Option<StoredAuthorization>, Self::Error>;
    async fn save(&self, authorization: StoredAuthorization) -> Result<(), Self::Error>;
}

/// In-memory implementation of [`AuthorizationStorage`].
#[derive(Clone, Default)]
pub struct InMemoryAuthorizationStorage {
    authorization: Arc<Mutex<Option<StoredAuthorization>>>,
}

#[async_trait]
impl AuthorizationStorage for InMemoryAuthorizationStorage {
    type Error = std::convert::Infallible;

    async fn load(&self) -> Result<Option<StoredAuthorization>, Self::Error> {
        Ok(self.authorization.lock().await.clone())
    }

    async fn save(&self, authorization: StoredAuthorization) -> Result<(), Self::Error> {
        *self.authorization.lock().await = Some(authorization);
        Ok(())
    }
}

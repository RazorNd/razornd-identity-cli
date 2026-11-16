/*
 * Copyright 2026 Daniil <RazorNd> Razorenov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use async_trait::async_trait;
use std::time::Duration;

/// Access token returned by a [`TokenProvider`].
///
/// Its debug representation intentionally does not reveal the token value.
pub struct AccessToken(String);

impl AccessToken {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Consumes the token and returns its secret value.
    pub fn into_secret(self) -> String {
        self.0
    }

    /// Exposes the token for use in an `Authorization` header.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccessToken([REDACTED])")
    }
}

/// Refresh token returned alongside an access token.
///
/// Its debug representation intentionally does not reveal the token value.
pub struct RefreshToken(String);

impl RefreshToken {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Exposes the token for use in a refresh-token request.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Consumes the token and returns its secret value.
    pub fn into_secret(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RefreshToken([REDACTED])")
    }
}

/// Tokens and lifetime returned by an authorization flow.
pub struct Authorization {
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
    expires_in: Option<Duration>,
}

impl Authorization {
    pub fn new(
        access_token: AccessToken,
        refresh_token: Option<RefreshToken>,
        expires_in: Option<Duration>,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_in,
        }
    }

    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    pub fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }

    pub fn expires_in(&self) -> Option<Duration> {
        self.expires_in
    }
}

/// Performs an authorization flow and returns all token data needed for storage.
#[async_trait]
pub trait AuthorizationProvider<E>: Send + Sync
where
    E: Send,
{
    async fn authorize(&self) -> Result<Authorization, E>;
}

/// Provides an access token suitable for calling the identity service.
#[async_trait]
pub trait TokenProvider<E>: Send + Sync
where
    E: Send,
{
    async fn access_token(&self) -> Result<AccessToken, E>;
}

#[async_trait]
impl<E, A> TokenProvider<E> for A
where
    E: Send,
    A: AuthorizationProvider<E>,
{
    async fn access_token(&self) -> Result<AccessToken, E> {
        self.authorize()
            .await
            .map(|authorization| authorization.access_token)
    }
}

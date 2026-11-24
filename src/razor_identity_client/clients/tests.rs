use super::*;
use crate::razor_identity_client::tests::client;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{bearer_token, body_json, method, path},
};

fn client_details(client_id: &str) -> Value {
    json!({
        "clientId": client_id,
        "clientName": "Example client",
        "clientAuthenticationMethods": ["client_secret_basic"],
        "authorizationGrantTypes": ["client_credentials"],
        "redirectUris": [],
        "scopes": ["profile"],
        "tokenSettings": {
            "authorizationCodeTimeToLive": "PT5M",
            "accessTokenTimeToLive": "PT5M",
            "accessTokenFormat": "self-contained",
            "reuseRefreshTokens": true,
            "refreshTokenTimeToLive": "PT1H"
        }
    })
}

#[tokio::test]
async fn creates_client_and_returns_generated_secret_only_in_creation_result() {
    let server = MockServer::start().await;
    let mut reply = client_details("issued-id");
    reply["clientSecret"] = json!("one-time-secret");
    Mock::given(method("POST"))
        .and(path("/api/admin/clients"))
        .and(bearer_token("test-token"))
        .and(body_json(json!({
            "clientName": "Example client",
            "clientAuthenticationMethods": ["client_secret_basic"],
            "authorizationGrantTypes": ["client_credentials"],
            "scopes": ["profile"]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(reply))
        .expect(1)
        .mount(&server)
        .await;

    let created = client(&server)
        .create_client(&CreateClientRequest {
            client_name: "Example client".to_owned(),
            client_authentication_methods: [ClientAuthenticationMethod::ClientSecretBasic].into(),
            authorization_grant_types: [ClientGrantType::ClientCredentials].into(),
            scopes: ["profile".to_owned()].into(),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(created.details.client_id, "issued-id");
    assert_eq!(created.client_secret.as_deref(), Some("one-time-secret"));
    assert!(!format!("{created:?}").contains("one-time-secret"));
}

#[tokio::test]
async fn creates_public_client_without_a_secret_with_token_overrides() {
    let server = MockServer::start().await;
    let mut reply = client_details("public-id");
    reply["clientAuthenticationMethods"] = json!(["none"]);
    reply["authorizationGrantTypes"] = json!(["authorization_code"]);
    reply["redirectUris"] = json!(["http://127.0.0.1:1234/callback"]);
    reply["tokenSettings"]["accessTokenFormat"] = json!("reference");
    reply["tokenSettings"]["reuseRefreshTokens"] = json!(false);
    Mock::given(method("POST"))
        .and(path("/api/admin/clients"))
        .and(body_json(json!({
            "clientName": "Example client",
            "clientAuthenticationMethods": ["none"],
            "authorizationGrantTypes": ["authorization_code"],
            "redirectUris": ["http://127.0.0.1:1234/callback"],
            "tokenSettings": {"accessTokenFormat": "reference", "reuseRefreshTokens": false}
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(reply))
        .expect(1)
        .mount(&server)
        .await;

    let created = client(&server)
        .create_client(&CreateClientRequest {
            client_name: "Example client".to_owned(),
            client_authentication_methods: [ClientAuthenticationMethod::None].into(),
            authorization_grant_types: [ClientGrantType::AuthorizationCode].into(),
            redirect_uris: ["http://127.0.0.1:1234/callback".to_owned()].into(),
            token_settings: ClientTokenSettingsRequest {
                access_token_format: Some(ClientAccessTokenFormat::Reference),
                reuse_refresh_tokens: Some(false),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(created.client_secret.is_none());
    assert!(!created.details.token_settings.reuse_refresh_tokens);
}

#[tokio::test]
async fn gets_patches_and_deletes_by_encoded_client_id() {
    let server = MockServer::start().await;
    let id = "client id?x";
    let endpoint = "/api/admin/clients/client%20id%3Fx";
    let reply = client_details(id);
    Mock::given(method("GET"))
        .and(path(endpoint))
        .and(bearer_token("test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&reply))
        .expect(1)
        .mount(&server)
        .await;

    let mut patched = reply;
    patched["scopes"] = json!(["email"]);
    patched["tokenSettings"]["accessTokenTimeToLive"] = json!("PT15M");
    patched["tokenSettings"]["reuseRefreshTokens"] = json!(false);
    Mock::given(method("PATCH"))
        .and(path(endpoint))
        .and(bearer_token("test-token"))
        .and(body_json(json!({
            "scopes": {"add": ["email"], "remove": ["profile"]},
            "tokenSettings": {"accessTokenTimeToLive": "PT15M", "reuseRefreshTokens": false}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(patched))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(endpoint))
        .and(bearer_token("test-token"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    assert_eq!(client.get_client(id).await.unwrap().unwrap().client_id, id);
    let updated = client
        .update_client(
            id,
            &UpdateClientRequest {
                scopes: SetChanges {
                    add: ["email".to_owned()].into(),
                    remove: ["profile".to_owned()].into(),
                },
                token_settings: ClientTokenSettingsRequest {
                    access_token_time_to_live: Some("PT15M".to_owned()),
                    reuse_refresh_tokens: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.scopes, ["email".to_owned()].into());
    assert_eq!(updated.token_settings.access_token_time_to_live, "PT15M");
    assert!(client.delete_client(id).await.unwrap());
}

#[tokio::test]
async fn maps_missing_clients_conflict_and_forbidden() {
    let server = MockServer::start().await;
    Mock::given(path("/api/admin/clients/missing"))
        .respond_with(ResponseTemplate::new(404))
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/admin/clients"))
        .respond_with(ResponseTemplate::new(409))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/admin/clients/restricted"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    assert!(client.get_client("missing").await.unwrap().is_none());
    assert!(
        client
            .update_client(
                "missing",
                &UpdateClientRequest {
                    client_name: Some("New name".to_owned()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(!client.delete_client("missing").await.unwrap());
    assert!(matches!(
        client.create_client(&CreateClientRequest::default()).await,
        Err(RazorIdentityClientError::ClientAlreadyExists)
    ));
    assert!(matches!(
        client.get_client("restricted").await,
        Err(RazorIdentityClientError::UnexpectedStatus {
            status: StatusCode::FORBIDDEN,
            ..
        })
    ));
    assert!(matches!(
        client.delete_client("..").await,
        Err(RazorIdentityClientError::InvalidClientId)
    ));
}

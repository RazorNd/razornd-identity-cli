use crate::client::IdentityClient;
use anyhow::{Result, bail, ensure};
use clap::{ArgAction, Args, Subcommand, builder::PossibleValuesParser};
use dialoguer::Confirm;
use razornd_identity_cli::oidc::SupportedScopesProvider;
use razornd_identity_cli::razor_identity_client::{
    ClientAccessTokenFormat, ClientAuthenticationMethod, ClientGrantType,
    ClientTokenSettingsRequest, CreateClientRequest, OAuthClient, RazorIdentityClientError,
    SetChanges, UpdateClientRequest,
};
use reqwest::StatusCode;
use std::{error::Error, fmt::Display, io::IsTerminal};

mod lifetime;
mod wizard;

use lifetime::parse_lifetime;
use wizard::ClientView;

#[derive(Debug, Subcommand)]
pub(super) enum ClientCommand {
    /// Register a client (opens a wizard when run in a terminal without options)
    Create(CreateClientArgs),
    /// Get a client by its ID
    Get { client_id: String },
    /// Update a client (opens a wizard when run in a terminal without options)
    Update(UpdateClientArgs),
    /// Permanently delete a client registration
    Delete {
        client_id: String,
        /// Skip confirmation (required when running outside a terminal)
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
pub(super) struct CreateClientArgs {
    /// Display name (required when supplying options)
    #[arg(long, value_parser = parse_name)]
    name: Option<String>,
    /// Client authentication method (repeatable; required when supplying options)
    #[arg(long, value_parser = authentication_method_parser())]
    auth_method: Vec<ClientAuthenticationMethod>,
    /// Authorization grant type (repeatable; required when supplying options)
    #[arg(long, value_parser = grant_type_parser())]
    grant_type: Vec<ClientGrantType>,
    /// Redirect URI (repeatable; required with authorization_code)
    #[arg(long, value_parser = parse_nonblank)]
    redirect_uri: Vec<String>,
    /// Registered scope (repeatable)
    #[arg(long, value_parser = parse_nonblank)]
    scope: Vec<String>,
    #[command(flatten)]
    token_settings: TokenSettingsArgs,
}

impl From<CreateClientArgs> for CreateClientRequest {
    fn from(args: CreateClientArgs) -> Self {
        Self {
            client_name: args.name.unwrap_or_default(),
            client_authentication_methods: args.auth_method.into_iter().collect(),
            authorization_grant_types: args.grant_type.into_iter().collect(),
            redirect_uris: args.redirect_uri.into_iter().collect(),
            scopes: args.scope.into_iter().collect(),
            token_settings: args.token_settings.into(),
        }
    }
}

#[derive(Debug, Args)]
pub(super) struct UpdateClientArgs {
    client_id: String,
    /// Change the display name
    #[arg(long, value_parser = parse_name)]
    name: Option<String>,
    /// Add a client authentication method (repeatable)
    #[arg(long, value_parser = authentication_method_parser())]
    add_auth_method: Vec<ClientAuthenticationMethod>,
    /// Remove a client authentication method (repeatable)
    #[arg(long, value_parser = authentication_method_parser())]
    remove_auth_method: Vec<ClientAuthenticationMethod>,
    /// Add an authorization grant type (repeatable)
    #[arg(long, value_parser = grant_type_parser())]
    add_grant_type: Vec<ClientGrantType>,
    /// Remove an authorization grant type (repeatable)
    #[arg(long, value_parser = grant_type_parser())]
    remove_grant_type: Vec<ClientGrantType>,
    /// Add a redirect URI (repeatable)
    #[arg(long, value_parser = parse_nonblank)]
    add_redirect_uri: Vec<String>,
    /// Remove a redirect URI (repeatable)
    #[arg(long, value_parser = parse_nonblank)]
    remove_redirect_uri: Vec<String>,
    /// Add a registered scope (repeatable)
    #[arg(long, value_parser = parse_nonblank)]
    add_scope: Vec<String>,
    /// Remove a scope (repeatable)
    #[arg(long, value_parser = parse_nonblank)]
    remove_scope: Vec<String>,
    #[command(flatten)]
    token_settings: TokenSettingsArgs,
}

impl UpdateClientArgs {
    fn into_request(self) -> (String, UpdateClientRequest) {
        let request = UpdateClientRequest {
            client_name: self.name,
            client_authentication_methods: changes(self.add_auth_method, self.remove_auth_method),
            authorization_grant_types: changes(self.add_grant_type, self.remove_grant_type),
            redirect_uris: changes(self.add_redirect_uri, self.remove_redirect_uri),
            scopes: changes(self.add_scope, self.remove_scope),
            token_settings: self.token_settings.into(),
        };
        (self.client_id, request)
    }
}

#[derive(Debug, Args)]
struct TokenSettingsArgs {
    /// Authorization code lifetime (ISO 8601 duration, e.g. PT5M)
    #[arg(long, value_parser = parse_lifetime)]
    authorization_code_ttl: Option<String>,
    /// Access token lifetime (ISO 8601 duration, e.g. PT15M)
    #[arg(long, value_parser = parse_lifetime)]
    access_token_ttl: Option<String>,
    /// Refresh token lifetime (ISO 8601 duration, e.g. PT1H)
    #[arg(long, value_parser = parse_lifetime)]
    refresh_token_ttl: Option<String>,
    /// Format for access tokens
    #[arg(long, value_parser = access_token_format_parser())]
    access_token_format: Option<ClientAccessTokenFormat>,
    /// Whether a refresh token can be used again
    #[arg(long, action = ArgAction::Set, value_name = "true|false")]
    reuse_refresh_tokens: Option<bool>,
}

impl From<TokenSettingsArgs> for ClientTokenSettingsRequest {
    fn from(args: TokenSettingsArgs) -> Self {
        Self {
            authorization_code_time_to_live: args.authorization_code_ttl,
            access_token_time_to_live: args.access_token_ttl,
            refresh_token_time_to_live: args.refresh_token_ttl,
            access_token_format: args.access_token_format,
            reuse_refresh_tokens: args.reuse_refresh_tokens,
        }
    }
}

impl ClientCommand {
    pub(super) async fn run(
        self,
        client: &IdentityClient,
        scope_provider: &impl SupportedScopesProvider,
    ) -> Result<()> {
        let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        match self {
            Self::Create(args) => create(client, scope_provider, args.into(), terminal).await,
            Self::Get { client_id } => {
                println!("{}", ClientView::from(&get(client, &client_id).await?));
                Ok(())
            }
            Self::Update(args) => {
                let (client_id, request) = args.into_request();
                update(client, scope_provider, &client_id, request, terminal).await
            }
            Self::Delete { client_id, yes } => delete(client, &client_id, yes, terminal).await,
        }
    }
}

async fn create(
    client: &IdentityClient,
    scope_provider: &impl SupportedScopesProvider,
    request: CreateClientRequest,
    terminal: bool,
) -> Result<()> {
    let request = if request == CreateClientRequest::default() {
        ensure!(
            terminal,
            "Outside a terminal, specify --name, --auth-method and --grant-type (see client create --help)"
        );
        let Some(request) = wizard::create(scope_provider).await? else {
            return Ok(());
        };
        request
    } else {
        request
    };
    validate_create(&request)?;
    let created = client.create_client(&request).await.map_err(client_error)?;
    println!(
        "Created OAuth2 client\n{}",
        ClientView::from(&created.details)
    );
    if let Some(secret) = created.client_secret {
        println!("Client secret: {secret}");
        eprintln!("Save this client secret now; it will not be shown again.");
    }
    Ok(())
}

async fn get(client: &IdentityClient, client_id: &str) -> Result<OAuthClient> {
    client
        .get_client(client_id)
        .await
        .map_err(client_error)?
        .ok_or_else(|| not_found(client_id))
}

async fn update(
    client: &IdentityClient,
    scope_provider: &impl SupportedScopesProvider,
    client_id: &str,
    request: UpdateClientRequest,
    terminal: bool,
) -> Result<()> {
    let request = if request.is_empty() {
        ensure!(
            terminal,
            "Outside a terminal, specify at least one change, e.g. --add-scope profile (see client update --help)"
        );
        let current = get(client, client_id).await?;
        let Some(request) = wizard::update(scope_provider, &current).await? else {
            return Ok(());
        };
        request
    } else {
        request
    };
    validate_update(&request)?;
    let updated = client
        .update_client(client_id, &request)
        .await
        .map_err(client_error)?
        .ok_or_else(|| not_found(client_id))?;
    println!("Updated OAuth2 client\n{}", ClientView::from(&updated));
    Ok(())
}

async fn delete(client: &IdentityClient, client_id: &str, yes: bool, terminal: bool) -> Result<()> {
    if !yes {
        ensure!(terminal, "Pass --yes to delete a client outside a terminal");
        if !Confirm::new()
            .with_prompt(format!("Permanently delete OAuth2 client {client_id:?}?"))
            .default(false)
            .interact_opt()?
            .unwrap_or(false)
        {
            return Ok(());
        }
    }
    if !client
        .delete_client(client_id)
        .await
        .map_err(client_error)?
    {
        return Err(not_found(client_id));
    }
    println!("Deleted OAuth2 client {client_id:?}");
    Ok(())
}

fn not_found(client_id: &str) -> anyhow::Error {
    anyhow::anyhow!("OAuth2 client {client_id:?} not found")
}

fn client_error<E: Error + Send + Sync + 'static>(
    error: RazorIdentityClientError<E>,
) -> anyhow::Error {
    match error {
        RazorIdentityClientError::UnexpectedStatus { status, .. } => match status {
            StatusCode::UNAUTHORIZED => {
                anyhow::anyhow!("Not authorized; sign in again with `auth login`")
            }
            StatusCode::FORBIDDEN => {
                anyhow::anyhow!("Client management requires ROLE_ADMIN and the clients:admin scope")
            }
            StatusCode::BAD_REQUEST => anyhow::anyhow!(
                "The service rejected the client configuration (HTTP 400); check protocol settings and registered scopes"
            ),
            _ => anyhow::anyhow!("Identity service returned HTTP {status}"),
        },
        other => other.into(),
    }
}

fn validate_client_config(request: &CreateClientRequest) -> Result<()> {
    parse_name(&request.client_name).map_err(anyhow::Error::msg)?;
    let methods = &request.client_authentication_methods;
    ensure!(
        !methods.is_empty(),
        "Specify at least one authentication method"
    );
    ensure!(
        !methods.contains(&ClientAuthenticationMethod::None) || methods.len() == 1,
        "The none authentication method cannot be combined with other methods"
    );
    ensure!(
        !request.authorization_grant_types.is_empty(),
        "Specify at least one authorization grant type"
    );
    ensure!(
        !request
            .authorization_grant_types
            .contains(&ClientGrantType::AuthorizationCode)
            || !request.redirect_uris.is_empty(),
        "The authorization_code grant requires at least one redirect URI"
    );
    Ok(())
}

fn validate_create(request: &CreateClientRequest) -> Result<()> {
    ensure!(
        !request.client_name.is_empty()
            && !request.client_authentication_methods.is_empty()
            && !request.authorization_grant_types.is_empty(),
        "Specify --name, at least one --auth-method and at least one --grant-type"
    );
    validate_client_config(request)
}

fn validate_update(request: &UpdateClientRequest) -> Result<()> {
    ensure!(!request.is_empty(), "No client changes specified");
    if let Some(name) = &request.client_name {
        parse_name(name).map_err(anyhow::Error::msg)?;
    }
    ensure_disjoint(
        &request.client_authentication_methods,
        "authentication method",
    )?;
    ensure_disjoint(&request.authorization_grant_types, "grant type")?;
    ensure_disjoint(&request.redirect_uris, "redirect URI")?;
    ensure_disjoint(&request.scopes, "scope")?;
    Ok(())
}

fn ensure_disjoint<T: Ord + Display>(changes: &SetChanges<T>, field: &str) -> Result<()> {
    if let Some(value) = changes.add.intersection(&changes.remove).next() {
        bail!("Cannot both add and remove {field} {:?}", value.to_string());
    }
    Ok(())
}

fn changes<T: Ord>(add: Vec<T>, remove: Vec<T>) -> SetChanges<T> {
    SetChanges {
        add: add.into_iter().collect(),
        remove: remove.into_iter().collect(),
    }
}

fn parse_name(value: &str) -> Result<String, &'static str> {
    if value.trim().is_empty() {
        return Err("Client name cannot be blank");
    }
    if value.encode_utf16().count() > 200 {
        return Err("Client name cannot exceed 200 UTF-16 code units");
    }
    Ok(value.to_owned())
}

fn parse_nonblank(value: &str) -> Result<String, &'static str> {
    if value.trim().is_empty() {
        return Err("Value cannot be blank");
    }
    Ok(value.to_owned())
}

fn authentication_method_parser()
-> impl clap::builder::TypedValueParser<Value = ClientAuthenticationMethod> {
    use clap::builder::TypedValueParser;
    PossibleValuesParser::new(
        ClientAuthenticationMethod::VALUES
            .iter()
            .map(|v| v.as_str()),
    )
    .map(|value| find_value(ClientAuthenticationMethod::VALUES, &value))
}

fn grant_type_parser() -> impl clap::builder::TypedValueParser<Value = ClientGrantType> {
    use clap::builder::TypedValueParser;
    PossibleValuesParser::new(ClientGrantType::VALUES.iter().map(|v| v.as_str()))
        .map(|value| find_value(ClientGrantType::VALUES, &value))
}

fn access_token_format_parser()
-> impl clap::builder::TypedValueParser<Value = ClientAccessTokenFormat> {
    use clap::builder::TypedValueParser;
    PossibleValuesParser::new(ClientAccessTokenFormat::VALUES.iter().map(|v| v.as_str()))
        .map(|value| find_value(ClientAccessTokenFormat::VALUES, &value))
}

fn find_value<T: Copy + Display>(values: &[T], value: &str) -> T {
    *values
        .iter()
        .find(|v| v.to_string() == value)
        .expect("clap already validated the possible value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;
    use serde_json::{json, to_value};

    fn parse(args: &[&str]) -> ClientCommand {
        let cli =
            Cli::try_parse_from(["cli", "client"].into_iter().chain(args.iter().copied())).unwrap();
        let Command::Client { command } = cli.command else {
            panic!("expected a client command");
        };
        *command
    }

    #[test]
    fn no_options_select_wizard_inputs_but_partial_create_fails_validation() {
        let ClientCommand::Create(args) = parse(&["create"]) else {
            panic!("expected create");
        };
        assert_eq!(
            CreateClientRequest::from(args),
            CreateClientRequest::default()
        );
        let ClientCommand::Update(args) = parse(&["update", "id"]) else {
            panic!("expected update");
        };
        assert!(args.into_request().1.is_empty());
        assert!(Cli::try_parse_from(["cli", "client", "update"]).is_err());

        let ClientCommand::Create(args) = parse(&["create", "--scope", "profile"]) else {
            panic!("expected create");
        };
        let request = CreateClientRequest::from(args);
        assert_ne!(request, CreateClientRequest::default());
        assert!(validate_create(&request).is_err());
    }

    #[test]
    fn parses_repeatable_registration_options_and_checks_combinations() {
        let ClientCommand::Create(args) = parse(&[
            "create",
            "--name",
            "Test client",
            "--auth-method",
            "none",
            "--grant-type",
            "authorization_code",
            "--scope",
            "profile",
            "--scope",
            "email",
        ]) else {
            panic!("expected create");
        };
        let mut request = CreateClientRequest::from(args);
        assert_eq!(
            request.scopes,
            ["email".to_owned(), "profile".to_owned()].into()
        );
        assert!(
            validate_create(&request)
                .unwrap_err()
                .to_string()
                .contains("redirect URI")
        );
        request
            .redirect_uris
            .insert("https://example.com/callback".to_owned());
        assert!(validate_create(&request).is_ok());
        request
            .client_authentication_methods
            .insert(ClientAuthenticationMethod::ClientSecretBasic);
        assert!(
            validate_create(&request)
                .unwrap_err()
                .to_string()
                .contains("cannot be combined")
        );
    }

    #[test]
    fn parses_patch_deltas_and_preserves_explicit_false() {
        let ClientCommand::Update(args) = parse(&[
            "update",
            "id",
            "--add-scope",
            "email",
            "--remove-scope",
            "profile",
            "--add-grant-type",
            "urn:ietf:params:oauth:grant-type:device_code",
            "--access-token-ttl",
            "PT15M",
            "--access-token-format",
            "reference",
            "--reuse-refresh-tokens",
            "false",
        ]) else {
            panic!("expected update");
        };
        let (id, request) = args.into_request();
        assert_eq!(id, "id");
        assert!(validate_update(&request).is_ok());
        assert_eq!(
            to_value(request).unwrap(),
            json!({
                "scopes": {"add": ["email"], "remove": ["profile"]},
                "authorizationGrantTypes": {"add": ["urn:ietf:params:oauth:grant-type:device_code"]},
                "tokenSettings": {
                    "accessTokenTimeToLive": "PT15M",
                    "accessTokenFormat": "reference",
                    "reuseRefreshTokens": false
                }
            })
        );
    }

    #[test]
    fn rejects_conflicting_patch_operations() {
        let ClientCommand::Update(args) = parse(&[
            "update",
            "id",
            "--add-scope",
            "profile",
            "--remove-scope",
            "profile",
        ]) else {
            panic!("expected update");
        };
        let error = validate_update(&args.into_request().1).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Cannot both add and remove scope \"profile\""
        );
    }

    #[test]
    fn parses_delete_confirmation_flag() {
        assert!(matches!(
            parse(&["delete", "id", "--yes"]),
            ClientCommand::Delete { yes: true, .. }
        ));
        assert!(matches!(
            parse(&["delete", "id"]),
            ClientCommand::Delete { yes: false, .. }
        ));
    }
}

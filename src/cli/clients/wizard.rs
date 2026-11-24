use super::{
    lifetime::duration, parse_lifetime, parse_name, parse_nonblank, validate_client_config,
};
use anyhow::Result;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use openidconnect::Scope;
use razornd_identity_cli::oidc::SupportedScopesProvider;
use razornd_identity_cli::razor_identity_client::{
    ClientAccessTokenFormat, ClientAuthenticationMethod, ClientGrantType, ClientTokenSettings,
    ClientTokenSettingsRequest, CreateClientRequest, OAuthClient, SetChanges, UpdateClientRequest,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Write},
    time::Duration,
};

pub(super) async fn create(
    scope_provider: &impl SupportedScopesProvider,
) -> Result<Option<CreateClientRequest>> {
    let client_name = read_name(None)?;
    eprintln!(
        "Use authorization_code for user sign-in or client_credentials for service-to-service access."
    );
    let Some(authorization_grant_types) = choose_set(
        "Authorization grant types (Space to toggle, Enter to accept)",
        ClientGrantType::VALUES,
        &BTreeSet::new(),
        |choices| !choices.is_empty(),
        "Select at least one grant type.",
    )?
    else {
        return Ok(None);
    };
    eprintln!(
        "Use none for a public client or client_secret_basic for a client that can keep a secret."
    );
    let Some(client_authentication_methods) = choose_auth_methods(&BTreeSet::new())? else {
        return Ok(None);
    };
    let redirect_uris = read_values(
        "redirect URI",
        authorization_grant_types.contains(&ClientGrantType::AuthorizationCode),
    )?;
    let Some(scopes) = choose_scopes(scope_provider, None, &BTreeSet::new()).await? else {
        return Ok(None);
    };
    let mut request = CreateClientRequest {
        client_name,
        client_authentication_methods,
        authorization_grant_types,
        redirect_uris,
        scopes,
        ..Default::default()
    };
    if confirm("Customize token settings?")? {
        edit_token_settings(&mut request.token_settings, true)?;
    }
    validate_client_config(&request)?;
    eprintln!("\nNew OAuth2 client\n{}", ClientView::from(&request));
    Ok(confirm("Create this client?")?.then_some(request))
}

pub(super) async fn update(
    scope_provider: &impl SupportedScopesProvider,
    current: &OAuthClient,
) -> Result<Option<UpdateClientRequest>> {
    let mut draft = draft_from(current);
    eprintln!("Current OAuth2 client\n{}", ClientView::from(current));
    loop {
        let action = Select::new()
            .with_prompt("Edit client")
            .items([
                "Name",
                "Authentication methods",
                "Authorization grant types",
                "Redirect URIs",
                "Scopes",
                "Token settings",
                "Review changes",
                "Cancel",
            ])
            .default(6)
            .interact_opt()?;
        match action {
            Some(0) => draft.client_name = read_name(Some(&draft.client_name))?,
            Some(1) => {
                eprintln!("Changing authentication methods does not generate a new secret.");
                if let Some(values) = choose_auth_methods(&draft.client_authentication_methods)? {
                    draft.client_authentication_methods = values;
                }
            }
            Some(2) => {
                if let Some(values) = choose_set(
                    "Authorization grant types (Space to toggle, Enter to accept)",
                    ClientGrantType::VALUES,
                    &draft.authorization_grant_types,
                    |choices| !choices.is_empty(),
                    "Select at least one grant type.",
                )? {
                    draft.authorization_grant_types = values;
                }
            }
            Some(3) => edit_values("redirect URI", &mut draft.redirect_uris)?,
            Some(4) => {
                if let Some(scopes) =
                    choose_scopes(scope_provider, Some(&current.scopes), &draft.scopes).await?
                {
                    draft.scopes = scopes;
                }
            }
            Some(5) => edit_token_settings(&mut draft.token_settings, false)?,
            Some(6) => {
                let request = diff(current, &draft);
                if request.is_empty() {
                    eprintln!("No changes to apply.");
                    return Ok(None);
                }
                if let Err(error) = validate_client_config(&draft) {
                    eprintln!("{error}");
                    continue;
                }
                eprintln!("\nChanges to OAuth2 client {:?}", current.client_id);
                eprint!("{}", change_summary(current, &request));
                return Ok(confirm("Apply these changes?")?.then_some(request));
            }
            _ => return Ok(None),
        }
    }
}

fn read_name(current: Option<&str>) -> Result<String> {
    let input = Input::<String>::new()
        .with_prompt("Client name")
        .validate_with(|value: &String| parse_name(value).map(|_| ()));
    let input = if let Some(current) = current {
        input.default(current.to_owned())
    } else {
        input
    };
    Ok(input.interact_text()?)
}

fn confirm(prompt: &str) -> Result<bool> {
    Ok(Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact_opt()?
        .unwrap_or(false))
}

fn choose_auth_methods(
    current: &BTreeSet<ClientAuthenticationMethod>,
) -> Result<Option<BTreeSet<ClientAuthenticationMethod>>> {
    choose_set(
        "Authentication methods (Space to toggle, Enter to accept)",
        ClientAuthenticationMethod::VALUES,
        current,
        |choices| {
            !choices.is_empty()
                && (!choices.contains(&ClientAuthenticationMethod::None) || choices.len() == 1)
        },
        "Select at least one method. The none method cannot be combined with other methods.",
    )
}

async fn choose_scopes(
    scope_provider: &impl SupportedScopesProvider,
    existing: Option<&BTreeSet<String>>,
    selected: &BTreeSet<String>,
) -> Result<Option<BTreeSet<String>>> {
    // Discovery is optional for the wizard; an unavailable issuer must not block manual input.
    match tokio::time::timeout(Duration::from_secs(5), scope_provider.supported_scopes()).await {
        Ok(Ok(supported)) => {
            if let Some(options) = scope_options(supported, existing, selected) {
                return choose_set(
                    "Scopes (Space to toggle, Enter to accept)",
                    &options,
                    selected,
                    |_| true,
                    "",
                );
            }
            eprintln!("The provider did not advertise scopes. Enter scopes manually.");
        }
        _ => eprintln!("Could not load scopes from OIDC discovery. Enter scopes manually."),
    }

    if existing.is_some() {
        let mut scopes = selected.clone();
        edit_values("scope", &mut scopes)?;
        Ok(Some(scopes))
    } else {
        Ok(Some(read_values("scope", false)?))
    }
}

fn scope_options(
    supported: Option<&[Scope]>,
    existing: Option<&BTreeSet<String>>,
    selected: &BTreeSet<String>,
) -> Option<Vec<String>> {
    let mut options: BTreeSet<_> = supported?
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    if options.is_empty() {
        return None;
    }
    options.extend(existing.into_iter().flatten().cloned());
    options.extend(selected.iter().cloned());
    Some(options.into_iter().collect())
}

fn choose_set<T: Clone + Ord + Display>(
    prompt: &str,
    values: &[T],
    current: &BTreeSet<T>,
    is_valid: impl Fn(&BTreeSet<T>) -> bool,
    error: &str,
) -> Result<Option<BTreeSet<T>>> {
    let labels: Vec<_> = values
        .iter()
        .map(|value| visible(&value.to_string()))
        .collect();
    let mut defaults: Vec<_> = values.iter().map(|value| current.contains(value)).collect();
    loop {
        let Some(selected) = MultiSelect::new()
            .with_prompt(prompt)
            .items(&labels)
            .defaults(&defaults)
            .interact_opt()?
        else {
            return Ok(None);
        };
        let choices = selected.iter().map(|&i| values[i].clone()).collect();
        if is_valid(&choices) {
            return Ok(Some(choices));
        }
        eprintln!("{error}");
        defaults.fill(false);
        for i in selected {
            defaults[i] = true;
        }
    }
}

fn read_values(label: &str, required: bool) -> Result<BTreeSet<String>> {
    let mut values = BTreeSet::new();
    loop {
        let can_finish = !required || !values.is_empty();
        let prompt = if can_finish {
            format!("Add {label} (leave blank to finish)")
        } else {
            format!("Add {label} (required)")
        };
        let value = read_value(prompt, can_finish)?;
        if value.is_empty() {
            return Ok(values);
        }
        values.insert(value);
    }
}

fn read_value(prompt: String, allow_empty: bool) -> Result<String> {
    Ok(Input::<String>::new()
        .with_prompt(prompt)
        .allow_empty(allow_empty)
        .validate_with(move |value: &String| {
            if allow_empty && value.is_empty() {
                Ok(())
            } else {
                parse_nonblank(value).map(|_| ())
            }
        })
        .interact_text()?)
}

fn edit_values(label: &str, values: &mut BTreeSet<String>) -> Result<()> {
    loop {
        eprintln!("Current values: {}", display_set(values));
        let options = if values.is_empty() {
            &["Add", "Back"][..]
        } else {
            &["Add", "Remove", "Back"][..]
        };
        match Select::new()
            .with_prompt(format!("Edit {label} list"))
            .items(options)
            .default(options.len() - 1)
            .interact_opt()?
        {
            Some(0) => values.extend(read_values(label, false)?),
            Some(1) if !values.is_empty() => {
                let existing: Vec<_> = values.iter().cloned().collect();
                let labels: Vec<_> = existing.iter().map(|value| visible(value)).collect();
                if let Some(selected) = MultiSelect::new()
                    .with_prompt("Select values to remove (Space to toggle, Enter to accept)")
                    .items(&labels)
                    .interact_opt()?
                {
                    for index in selected {
                        values.remove(&existing[index]);
                    }
                }
            }
            _ => return Ok(()),
        }
    }
}

fn edit_token_settings(settings: &mut ClientTokenSettingsRequest, creating: bool) -> Result<()> {
    loop {
        let rows = token_rows(settings);
        let mut choices: Vec<_> = rows.iter().map(format_token_row).collect();
        choices.push("Back".to_owned());
        let Some(index) = Select::new()
            .with_prompt("Token settings")
            .items(&choices)
            .default(choices.len() - 1)
            .interact_opt()?
            .filter(|&index| index < rows.len())
        else {
            return Ok(());
        };
        let label = rows[index].0;
        match index {
            0 => edit_lifetime(
                label,
                &mut settings.authorization_code_time_to_live,
                creating,
            )?,
            1 => edit_lifetime(label, &mut settings.access_token_time_to_live, creating)?,
            2 => edit_lifetime(label, &mut settings.refresh_token_time_to_live, creating)?,
            3 => edit_setting(
                label,
                ClientAccessTokenFormat::VALUES,
                &mut settings.access_token_format,
                creating,
            )?,
            4 => edit_setting(
                label,
                &[true, false],
                &mut settings.reuse_refresh_tokens,
                creating,
            )?,
            _ => unreachable!(),
        }
    }
}

fn edit_lifetime(label: &str, current: &mut Option<String>, creating: bool) -> Result<()> {
    let blank = if creating {
        "use server default"
    } else {
        "keep current draft value"
    };
    let value = Input::<String>::new()
        .with_prompt(format!("{label} (e.g. PT15M, blank to {blank})"))
        .allow_empty(true)
        .validate_with(|value: &String| {
            if value.is_empty() {
                Ok(())
            } else {
                parse_lifetime(value).map(|_| ())
            }
        })
        .interact_text()?;
    if !value.is_empty() {
        *current = Some(value.to_ascii_uppercase());
    } else if creating {
        *current = None;
    }
    Ok(())
}

fn edit_setting<T: Copy + Display + PartialEq>(
    label: &str,
    values: &[T],
    current: &mut Option<T>,
    creating: bool,
) -> Result<()> {
    let mut labels: Vec<_> = values.iter().map(ToString::to_string).collect();
    if creating {
        labels.push("Server default".to_owned());
    }
    let default = values.iter().position(|value| Some(*value) == *current);
    if let Some(index) = Select::new()
        .with_prompt(label)
        .items(&labels)
        .default(default.unwrap_or(labels.len() - 1))
        .interact_opt()?
    {
        *current = values.get(index).copied();
    }
    Ok(())
}

fn draft_from(client: &OAuthClient) -> CreateClientRequest {
    CreateClientRequest {
        client_name: client.client_name.clone(),
        client_authentication_methods: client.client_authentication_methods.clone(),
        authorization_grant_types: client.authorization_grant_types.clone(),
        redirect_uris: client.redirect_uris.clone(),
        scopes: client.scopes.clone(),
        token_settings: settings_from(&client.token_settings),
    }
}

fn settings_from(settings: &ClientTokenSettings) -> ClientTokenSettingsRequest {
    ClientTokenSettingsRequest {
        authorization_code_time_to_live: Some(settings.authorization_code_time_to_live.clone()),
        access_token_time_to_live: Some(settings.access_token_time_to_live.clone()),
        access_token_format: Some(settings.access_token_format),
        reuse_refresh_tokens: Some(settings.reuse_refresh_tokens),
        refresh_token_time_to_live: Some(settings.refresh_token_time_to_live.clone()),
    }
}

fn diff(current: &OAuthClient, draft: &CreateClientRequest) -> UpdateClientRequest {
    let before = &current.token_settings;
    let after = &draft.token_settings;
    UpdateClientRequest {
        client_name: changed(&current.client_name, Some(&draft.client_name)).cloned(),
        client_authentication_methods: set_diff(
            &current.client_authentication_methods,
            &draft.client_authentication_methods,
        ),
        authorization_grant_types: set_diff(
            &current.authorization_grant_types,
            &draft.authorization_grant_types,
        ),
        redirect_uris: set_diff(&current.redirect_uris, &draft.redirect_uris),
        scopes: set_diff(&current.scopes, &draft.scopes),
        token_settings: ClientTokenSettingsRequest {
            authorization_code_time_to_live: changed_lifetime(
                &before.authorization_code_time_to_live,
                after.authorization_code_time_to_live.as_ref(),
            ),
            access_token_time_to_live: changed_lifetime(
                &before.access_token_time_to_live,
                after.access_token_time_to_live.as_ref(),
            ),
            access_token_format: changed(
                &before.access_token_format,
                after.access_token_format.as_ref(),
            )
            .copied(),
            reuse_refresh_tokens: changed(
                &before.reuse_refresh_tokens,
                after.reuse_refresh_tokens.as_ref(),
            )
            .copied(),
            refresh_token_time_to_live: changed_lifetime(
                &before.refresh_token_time_to_live,
                after.refresh_token_time_to_live.as_ref(),
            ),
        },
    }
}

fn changed<'a, T: PartialEq>(before: &T, after: Option<&'a T>) -> Option<&'a T> {
    after.filter(|after| *after != before)
}

fn changed_lifetime(before: &str, after: Option<&String>) -> Option<String> {
    after
        .filter(|after| {
            before != after.as_str()
                && !duration(before).is_some_and(|before| Some(before) == duration(after))
        })
        .cloned()
}

fn set_diff<T: Ord + Clone>(before: &BTreeSet<T>, after: &BTreeSet<T>) -> SetChanges<T> {
    SetChanges {
        add: after.difference(before).cloned().collect(),
        remove: before.difference(after).cloned().collect(),
    }
}

fn change_summary(current: &OAuthClient, request: &UpdateClientRequest) -> String {
    let mut lines = String::new();
    if let Some(name) = &request.client_name {
        let _ = writeln!(lines, "  Name: {:?} → {name:?}", current.client_name);
    }
    show_set_changes(
        &mut lines,
        "Authentication methods",
        &request.client_authentication_methods,
    );
    show_set_changes(
        &mut lines,
        "Grant types",
        &request.authorization_grant_types,
    );
    show_set_changes(&mut lines, "Redirect URIs", &request.redirect_uris);
    show_set_changes(&mut lines, "Scopes", &request.scopes);
    let before = token_rows(&settings_from(&current.token_settings));
    let after = token_rows(&request.token_settings);
    for ((label, previous), (_, next)) in before.into_iter().zip(after) {
        if let Some(next) = next {
            let _ = writeln!(
                lines,
                "  {label}: {} → {}",
                visible(previous.as_deref().unwrap_or_default()),
                visible(&next)
            );
        }
    }
    lines
}

fn show_set_changes<T: Display>(lines: &mut String, label: &str, changes: &SetChanges<T>) {
    if changes.is_empty() {
        return;
    }
    let items = changes
        .add
        .iter()
        .map(|value| format!("+{}", visible(&value.to_string())))
        .chain(
            changes
                .remove
                .iter()
                .map(|value| format!("−{}", visible(&value.to_string()))),
        )
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(lines, "  {label}: {items}");
}

pub(super) struct ClientView<'a> {
    id: Option<&'a str>,
    name: &'a str,
    authentication_methods: &'a BTreeSet<ClientAuthenticationMethod>,
    grant_types: &'a BTreeSet<ClientGrantType>,
    redirect_uris: &'a BTreeSet<String>,
    scopes: &'a BTreeSet<String>,
    token_settings: ClientTokenSettingsRequest,
}

impl<'a> From<&'a OAuthClient> for ClientView<'a> {
    fn from(client: &'a OAuthClient) -> Self {
        Self {
            id: Some(&client.client_id),
            name: &client.client_name,
            authentication_methods: &client.client_authentication_methods,
            grant_types: &client.authorization_grant_types,
            redirect_uris: &client.redirect_uris,
            scopes: &client.scopes,
            token_settings: settings_from(&client.token_settings),
        }
    }
}

impl<'a> From<&'a CreateClientRequest> for ClientView<'a> {
    fn from(client: &'a CreateClientRequest) -> Self {
        Self {
            id: None,
            name: &client.client_name,
            authentication_methods: &client.client_authentication_methods,
            grant_types: &client.authorization_grant_types,
            redirect_uris: &client.redirect_uris,
            scopes: &client.scopes,
            token_settings: client.token_settings.clone(),
        }
    }
}

impl Display for ClientView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(id) = self.id {
            writeln!(f, "Client ID: {}", visible(id))?;
        }
        writeln!(f, "Name: {}", visible(self.name))?;
        writeln!(
            f,
            "Authentication methods: {}",
            display_set(self.authentication_methods)
        )?;
        writeln!(f, "Grant types: {}", display_set(self.grant_types))?;
        writeln!(f, "Redirect URIs: {}", display_set(self.redirect_uris))?;
        writeln!(f, "Scopes: {}", display_set(self.scopes))?;
        write!(f, "Token settings:")?;
        for row in &token_rows(&self.token_settings) {
            write!(f, "\n  {}", format_token_row(row))?;
        }
        Ok(())
    }
}

type TokenRow = (&'static str, Option<String>);

fn token_rows(settings: &ClientTokenSettingsRequest) -> [TokenRow; 5] {
    [
        (
            "Authorization code TTL",
            settings.authorization_code_time_to_live.clone(),
        ),
        (
            "Access token TTL",
            settings.access_token_time_to_live.clone(),
        ),
        (
            "Refresh token TTL",
            settings.refresh_token_time_to_live.clone(),
        ),
        (
            "Access token format",
            settings.access_token_format.map(|value| value.to_string()),
        ),
        (
            "Reuse refresh tokens",
            settings.reuse_refresh_tokens.map(|value| value.to_string()),
        ),
    ]
}

fn format_token_row((label, value): &TokenRow) -> String {
    format!(
        "{label}: {}",
        visible(value.as_deref().unwrap_or("server default"))
    )
}

fn display_set(values: &BTreeSet<impl Display>) -> String {
    if values.is_empty() {
        return "(none)".to_owned();
    }
    values
        .iter()
        .map(|value| visible(&value.to_string()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn visible(value: &str) -> String {
    value.escape_debug().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value};

    fn registered_client() -> OAuthClient {
        OAuthClient {
            client_id: "issued-id".to_owned(),
            client_name: "Test client".to_owned(),
            client_authentication_methods: [ClientAuthenticationMethod::ClientSecretBasic].into(),
            authorization_grant_types: [ClientGrantType::ClientCredentials].into(),
            redirect_uris: BTreeSet::new(),
            scopes: ["openid".to_owned(), "profile".to_owned()].into(),
            token_settings: ClientTokenSettings {
                authorization_code_time_to_live: "PT5M".to_owned(),
                access_token_time_to_live: "PT5M".to_owned(),
                refresh_token_time_to_live: "PT1H".to_owned(),
                access_token_format: ClientAccessTokenFormat::SelfContained,
                reuse_refresh_tokens: true,
            },
        }
    }

    #[test]
    fn scope_choices_are_sorted_and_keep_existing_and_draft_values() {
        let supported = ["profile", "email", "profile"].map(|scope| Scope::new(scope.to_owned()));
        let existing = ["unpublished".to_owned(), "profile".to_owned()].into();
        let selected = ["manual".to_owned()].into();
        assert_eq!(
            scope_options(Some(&supported), Some(&existing), &selected).unwrap(),
            ["email", "manual", "profile", "unpublished"]
        );
        assert_eq!(scope_options(None, Some(&existing), &selected), None);
        assert_eq!(scope_options(Some(&[]), Some(&existing), &selected), None);
    }

    #[test]
    fn unedited_reverted_and_equivalent_values_produce_no_patch() {
        let current = registered_client();
        let mut draft = draft_from(&current);
        assert!(diff(&current, &draft).is_empty());

        draft.scopes.insert("email".to_owned());
        assert!(!diff(&current, &draft).is_empty());
        draft.scopes.remove("email");
        draft.token_settings.refresh_token_time_to_live = Some("PT60M".to_owned());
        assert!(diff(&current, &draft).is_empty());
    }

    #[test]
    fn patch_and_review_show_only_effective_changes() {
        let current = registered_client();
        let mut draft = draft_from(&current);
        draft.scopes.remove("profile");
        draft.scopes.insert("email".to_owned());
        draft.token_settings.access_token_time_to_live = Some("PT15M".to_owned());
        draft.token_settings.reuse_refresh_tokens = Some(false);

        let request = diff(&current, &draft);
        assert_eq!(
            change_summary(&current, &request),
            "  Scopes: +email, −profile\n  Access token TTL: PT5M → PT15M\n  Reuse refresh tokens: true → false\n"
        );
        assert_eq!(
            to_value(request).unwrap(),
            json!({
                "scopes": {"add": ["email"], "remove": ["profile"]},
                "tokenSettings": {"accessTokenTimeToLive": "PT15M", "reuseRefreshTokens": false}
            })
        );
    }
}

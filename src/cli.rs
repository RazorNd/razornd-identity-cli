use crate::client::IdentityTokenProvider;
use crate::{app::IdentityApp, client::IdentityClient};
use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use dialoguer::{Input, Password, Select};
use razornd_identity_cli::razor_identity_client::{
    Account, CreateAccountRequest, UpdateAccountRequest,
};
use std::io::{IsTerminal, Read};

#[derive(Debug, Parser)]
#[command(
    name = "razornd-identity",
    version,
    about = "Manage the razornd-identity server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage the CLI session
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Manage user accounts
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Authorize the CLI in your browser and replace the saved session
    Login,
    /// Remove the local CLI session
    ///
    /// Does not revoke the token or sign out of the browser.
    Logout,
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// Create a user account
    Create(CreateUserArgs),
    /// Get a user account
    Get { username: String },
    /// Update a user account
    Update(UpdateUserArgs),
    /// Disable a user account
    Disable { username: String },
}

#[derive(Debug, Args)]
struct CreateUserArgs {
    /// Username of the account to create (prompted for in an interactive terminal)
    username: Option<String>,
    /// Read the password from stdin; an empty password requests generation
    #[arg(long)]
    password_stdin: bool,
    /// Create the account in a disabled state
    #[arg(long)]
    disabled: bool,
}

#[derive(Debug, Args)]
struct UpdateUserArgs {
    /// Username of the account to update
    username: String,
    /// Prompt for a new password
    #[arg(
        long,
        conflicts_with = "password_stdin",
        required_unless_present_any = ["password_stdin", "enabled", "disabled"]
    )]
    password: bool,
    /// Read the new password from stdin
    #[arg(
        long,
        conflicts_with = "password",
        required_unless_present_any = ["password", "enabled", "disabled"]
    )]
    password_stdin: bool,
    /// Enable the account
    #[arg(
        long,
        alias = "enable",
        conflicts_with = "disabled",
        required_unless_present_any = ["password", "password_stdin", "disabled"]
    )]
    enabled: bool,
    /// Disable the account
    #[arg(
        long,
        alias = "disable",
        conflicts_with = "enabled",
        required_unless_present_any = ["password", "password_stdin", "enabled"]
    )]
    disabled: bool,
}

pub(crate) async fn run(app: IdentityApp) -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Auth { command } => command.run(app.token_provider()?).await,
        Command::User { command } => command.run(&app.client()?).await,
        Command::Completions { shell } => {
            generate(
                shell,
                &mut Cli::command(),
                "razornd-identity-cli",
                &mut std::io::stdout(),
            );
            Ok(())
        }
    }
}

impl AuthCommand {
    async fn run(self, token_provider: IdentityTokenProvider) -> Result<()> {
        match self {
            AuthCommand::Login => {
                token_provider
                    .reauthorize()
                    .await
                    .context("failed to log in to the CLI")?;
                println!("Logged in to the CLI.");
                Ok(())
            }
            AuthCommand::Logout => {
                token_provider
                    .clear_authorization()
                    .await
                    .context("failed to clear the local CLI session")?;
                println!("Logged out of the CLI. Your browser session is unchanged.");
                Ok(())
            }
        }
    }
}

impl UserCommand {
    async fn run(self, client: &IdentityClient) -> Result<()> {
        match self {
            UserCommand::Create(args) => create_user(client, args).await,
            UserCommand::Get { username } => get_user(client, &username).await,
            UserCommand::Update(args) => update_user(client, args).await,
            UserCommand::Disable { username } => disable_user(client, &username).await,
        }
    }
}

async fn create_user(client: &IdentityClient, args: CreateUserArgs) -> Result<()> {
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let username = match args.username {
        Some(username) => username,
        None if interactive => Input::<String>::new()
            .with_prompt("Username")
            .interact_text()?,
        None => bail!("username is required when running without an interactive terminal"),
    };

    let mut request = CreateAccountRequest::new(username);

    request.password = match (args.password_stdin, interactive) {
        (true, _) => read_password_from_stdin()?,
        (false, true) => read_password_interactive("Password (leave empty to generate one)")?,
        _ => None,
    };

    request.enabled = match (args.disabled, interactive) {
        (true, _) => false,
        (false, true) => read_user_enabled_interactive(|s| Ok(s.default(0).interact()? == 0))?,
        _ => true,
    };

    let created = client.create_account(&request).await?;
    println!(
        "Created user '{}' ({})",
        created.username,
        status_label(created.enabled)
    );
    if let Some(password) = created.generated_password {
        println!("Generated password: {password}");
        println!("Save this password now; it will not be shown again.");
    }
    Ok(())
}

async fn get_user(client: &IdentityClient, username: &str) -> Result<()> {
    match client.get_account(username).await? {
        Some(account) => print_account(&account),
        None => bail!("User '{username}' not found"),
    }
    Ok(())
}

async fn update_user(client: &IdentityClient, args: UpdateUserArgs) -> Result<()> {
    let password = if args.password {
        Some(read_required_password_interactive()?)
    } else if args.password_stdin {
        Some(read_required_password_from_stdin()?)
    } else {
        None
    };

    let enabled = match (args.enabled, args.disabled) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => None,
    };

    let request = UpdateAccountRequest { password, enabled };
    if request.password.is_none() && request.enabled.is_none() {
        bail!("No changes specified; use a password or status option");
    }

    match client.update_account(&args.username, &request).await? {
        Some(account) => {
            println!("Updated user '{}'", account.username);
            print_account(&account);
        }
        None => bail!("User '{}' not found", args.username),
    }
    Ok(())
}

async fn disable_user(client: &IdentityClient, username: &str) -> Result<()> {
    if client.disable_account(username).await? {
        println!("Disabled user '{username}'");
        Ok(())
    } else {
        bail!("User '{username}' not found")
    }
}

fn read_password_from_stdin() -> Result<Option<String>> {
    let mut password = String::new();
    std::io::stdin()
        .read_to_string(&mut password)
        .context("failed to read password from stdin")?;
    let password = password.trim_end_matches(['\r', '\n']);
    Ok((!password.is_empty()).then(|| password.to_owned()))
}

fn read_password_interactive(prompt: &str) -> Result<Option<String>> {
    let password = Password::new()
        .with_prompt(prompt)
        .allow_empty_password(true)
        .interact()?;
    Ok((!password.is_empty()).then_some(password))
}

fn read_required_password_interactive() -> Result<String> {
    Ok(Password::new().with_prompt("New password").interact()?)
}

fn read_required_password_from_stdin() -> Result<String> {
    read_password_from_stdin()?
        .ok_or_else(|| anyhow::anyhow!("password from stdin cannot be empty"))
}

fn read_user_enabled_interactive<F, R>(f: F) -> Result<R>
where
    F: FnOnce(Select) -> Result<R>,
{
    let select = Select::new()
        .with_prompt("Account status")
        .items(["Enabled", "Disabled"]);

    f(select)
}

fn print_account(account: &Account) {
    println!("Username: {}", account.username);
    println!("Status: {}", status_label(account.enabled));
}

fn status_label(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}

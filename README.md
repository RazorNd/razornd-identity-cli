# razornd-identity-cli

`razornd-identity-cli` is a command-line client for [razornd-identity](https://github.com/RazorNd/razornd-identity), RazorNd's identity and access management service. It manages user accounts and OAuth2 clients through the administrative API.

## Installation

1. Install a current stable Rust toolchain and Cargo using [rustup](https://rustup.rs/).
   The project uses Rust edition 2024, which requires Rust 1.85 or newer.
   Git and a working native build toolchain are also required.
2. Install the CLI directly from GitHub:

   ```bash
   cargo install --git https://github.com/RazorNd/razornd-identity-cli.git --locked
   ```

   Cargo downloads the repository, builds the CLI in release mode, and installs
   `razornd-identity-cli` into `$HOME/.cargo/bin` by default.
3. Ensure that Cargo's binary directory is in your `PATH`, then verify the installation:

   ```bash
   razornd-identity-cli --help
   ```

To update, run the installation command again. To remove the CLI, run
`cargo uninstall razornd-identity-cli`. For a specific branch, tag, or commit,
add Cargo's `--branch`, `--tag`, or `--rev` option to the installation command.
The compile-time configuration variables described below can also be set before
`cargo install`; changing them requires reinstalling the CLI (use `--force`).

## Authentication and configuration

The administrative API requires appropriate authorization. By default, the CLI uses the public OAuth client `razornd-identity-cli` with Authorization Code and PKCE (S256), without a client secret. It requests `openid profile accounts:admin clients:admin`. The registered callback is `http://127.0.0.1:0/oauth2/callback`; the CLI binds a free loopback port and sends the actual callback URI to the server. The server controls consent and the access token lifetime (six hours in the default server registration).

Override the following settings at compile time:

| Variable | Setting |
| --- | --- |
| `RAZORND_IDENTITY_ISSUER_URI` | Issuer URI |
| `RAZORND_IDENTITY_CLIENT_ID` | OAuth client ID |
| `RAZORND_IDENTITY_REDIRECT_URI` | Callback URI |
| `RAZORND_IDENTITY_SCOPES` | Whitespace-separated scopes; `openid` is always included |

For example, set `RAZORND_IDENTITY_SCOPES="openid profile accounts:admin"` when installing or building the CLI.

To sign in explicitly, run `razornd-identity-cli auth login`.
This starts browser authorization even if a token is already saved, and replaces the local
session only after a new token is saved. You can also skip this step:
`user` and `client` commands start authorization automatically when making a request without a usable cached token.

To sign out of the CLI, run `razornd-identity-cli auth logout`.
This removes the local token for the current issuer, client ID, and scope configuration.
It works offline and succeeds even if no token is stored. It does not revoke the token
on the server or sign out of the browser. The next API request starts authorization again.

## User accounts

The `user` commands use the administrative account endpoints under `/api/admin/accounts`. Create an account interactively, or provide the positional username. When prompted, an empty password asks the service to generate one and return it once:

```bash
razornd-identity-cli user create
razornd-identity-cli user create new-user
razornd-identity-cli user create new-user --disabled
printf '%s' "$USER_PASSWORD" | razornd-identity-cli user create new-user --password-stdin
```

Get, update, and disable accounts:

```bash
razornd-identity-cli user get new-user
razornd-identity-cli user update new-user --password --enabled
razornd-identity-cli user update new-user --password
printf '%s' "$USER_PASSWORD" | razornd-identity-cli user update new-user --password-stdin
razornd-identity-cli user update new-user --disabled
razornd-identity-cli user disable new-user
```

`user update` changes only the fields selected by its options. `--password` prompts for a new password; alternatively, `--password-stdin` reads it from stdin. These options conflict. Set account status explicitly with `--enabled` or `--disabled` (also available as `--enable` or `--disable`). At least one password or status option is required.

## OAuth2 clients

`client` commands use `/api/admin/clients` and require both the administrator role and the `clients:admin` scope. Only clients managed through this API can be retrieved, updated, or deleted; clients defined in server configuration, including the built-in CLI client, are not managed here.

Run `client create` or `client update <client-id>` in a terminal without configuration flags to open a wizard. The creation wizard previews the registration before sending it. The update wizard loads the current configuration and sends a single PATCH only after you review and confirm the changes.

The wizard offers scopes advertised in the issuer's OIDC `scopes_supported` metadata. Existing scopes stay available when editing even if they are not advertised. If the provider publishes no scopes or discovery is unavailable, the wizard accepts manual input instead. Scope flags do not require this lookup; the server validates scopes in both modes.

Use flags to run without prompts. The CLI never switches to the wizard when a configuration flag is supplied:

```bash
razornd-identity-cli client create --name "My service" \
  --auth-method client_secret_basic --grant-type client_credentials --scope profile
razornd-identity-cli client get "$CLIENT_ID"
razornd-identity-cli client update "$CLIENT_ID" --add-scope email --remove-scope profile \
  --access-token-ttl PT15M --reuse-refresh-tokens false
razornd-identity-cli client delete "$CLIENT_ID" --yes
```

Non-interactive creation requires `--name`, `--auth-method`, and `--grant-type`. Repeat flags to supply multiple methods, grants, redirect URIs, or scopes. Use `--auth-method none` on its own for a public client, and supply at least one `--redirect-uri` with `authorization_code`. Token lifetimes use ISO 8601 duration strings (for example, `PT15M`), and unspecified token settings use the server defaults.

Updates change only the supplied fields. Use matching `--add-*` and `--remove-*` flags to edit sets rather than replace them. `--reuse-refresh-tokens false` explicitly disables reuse; omitting the flag leaves it unchanged. See `client create --help` and `client update --help` for all options.

The server assigns the client ID; set `CLIENT_ID` to that value for the examples above. If it generates a client secret, the CLI prints it to stdout only at creation. Save it securely and avoid sending stdout to a shared log. Neither reading nor updating a client reveals or rotates its secret. Deletion permanently removes the registration and needs confirmation in a terminal or `--yes` in a script.

## Development

From the repository root, use `cargo run --` in place of `razornd-identity-cli` to run a command from source. For example:

```bash
cargo run -- user get new-user
```

Run the development checks with:

```bash
cargo fmt -- --check
cargo check
cargo test
cargo clippy -- -D warnings
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

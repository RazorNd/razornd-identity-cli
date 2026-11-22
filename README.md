# razornd-identity-cli

`razornd-identity-cli` is a command-line client for [razornd-identity](https://github.com/RazorNd/razornd-identity), RazorNd's identity and access management service. It is intended to provide convenient access to the service's user-management API and can grow to cover other service capabilities over time.

## Status

The service currently exposes administrative account endpoints under `/api/admin/accounts`:

- `POST /api/admin/accounts` — create an account. If `password` is omitted, the service generates one and returns it once.
- `GET /api/admin/accounts/{username}` — retrieve account details.
- `PATCH /api/admin/accounts/{username}` — update the password and/or enabled status.
- `DELETE /api/admin/accounts/{username}` — disable an account.

The API is protected by the identity service's administrative authorization, so clients must be configured with appropriate access.

By default, the CLI uses the public OAuth client `razornd-identity-cli` with Authorization Code and PKCE (S256), without a client secret. It requests `openid profile accounts:admin clients:admin`. The registered callback is `http://127.0.0.1:0/oauth2/callback`; the CLI binds a free loopback port and sends the actual callback URI to the server. The server controls consent and the access token lifetime (six hours in the default server registration).

Override the issuer, client ID, callback URI, or whitespace-separated scopes at compile time with `RAZORND_IDENTITY_ISSUER_URI`, `RAZORND_IDENTITY_CLIENT_ID`, `RAZORND_IDENTITY_REDIRECT_URI`, or `RAZORND_IDENTITY_SCOPES`. The `openid` scope is always included.

```bash
RAZORND_IDENTITY_SCOPES="openid profile accounts:admin" \
cargo run -- user get some-user
```

To sign out of the CLI, run `razornd-identity-cli auth logout` (or `cargo run -- auth logout`).
This removes the local token for the current issuer, client ID, and scope configuration.
It works offline and succeeds even if no token is stored. It does not revoke the token
on the server or sign out of the browser. The next `user` command starts authorization again.

Create an account interactively, or provide the positional username. When prompted, an empty password asks the service to generate one:

```bash
cargo run -- user create
cargo run -- user create new-user
cargo run -- user create new-user --disabled
printf '%s' "$USER_PASSWORD" | cargo run -- user create new-user --password-stdin
```

Get, update, and disable accounts:

```bash
cargo run -- user get new-user
cargo run -- user update new-user --password --enabled
cargo run -- user update new-user --password
printf '%s' "$USER_PASSWORD" | cargo run -- user update new-user --password-stdin
cargo run -- user update new-user --disabled
cargo run -- user disable new-user
```

`user update` changes only the fields selected by its options. `--password` prompts for a new password; alternatively, `--password-stdin` reads it from stdin. These options conflict. Set account status explicitly with `--enabled` or `--disabled` (also available as `--enable` or `--disable`). At least one password or status option is required.

## Development

Requires the Rust toolchain with Cargo. From the repository root:

```bash
cargo run
cargo fmt -- --check
cargo check
cargo test
cargo clippy -- -D warnings
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

# razornd-identity-cli

`razornd-identity-cli` is a command-line client for [razornd-identity](https://github.com/RazorNd/razornd-identity), RazorNd's identity and access management service. It is intended to provide convenient access to the service's user-management API and can grow to cover other service capabilities over time.

## Status

The service currently exposes administrative account endpoints under `/api/admin/accounts`:

- `POST /api/admin/accounts` — create an account. If `password` is omitted, the service generates one and returns it once.
- `GET /api/admin/accounts/{username}` — retrieve account details.
- `PATCH /api/admin/accounts/{username}` — update the password and/or enabled status.
- `DELETE /api/admin/accounts/{username}` — disable an account.

The API is protected by the identity service's administrative authorization, so clients must be configured with appropriate access.

The authorization request asks for `openid accounts:admin` by default. Configure the requested scopes as a whitespace-separated list with `RAZORND_IDENTITY_SCOPES`, in the same way as `RAZORND_IDENTITY_CLIENT_ID`. These `RAZORND_IDENTITY_*` settings are read at compile time:

```bash
RAZORND_IDENTITY_SCOPES="openid accounts:admin" \
RAZORND_IDENTITY_CLIENT_ID="http-client" \
cargo run -- user get some-user
```

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

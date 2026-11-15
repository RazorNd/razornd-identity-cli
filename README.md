# razornd-identity-cli

`razornd-identity-cli` is a command-line client for [razornd-identity](https://github.com/RazorNd/razornd-identity), RazorNd's identity and access management service. It is intended to provide convenient access to the service's user-management API and can grow to cover other service capabilities over time.

## Status

The service currently exposes administrative account endpoints under `/api/admin/accounts`:

- `POST /api/admin/accounts` — create an account. If `password` is omitted, the service generates one and returns it once.
- `GET /api/admin/accounts/{username}` — retrieve account details.
- `PATCH /api/admin/accounts/{username}` — update the password and/or enabled status.
- `DELETE /api/admin/accounts/{username}` — disable an account.

The CLI is an early-stage project; its implementation and command syntax are not yet available. The API is protected by the identity service's administrative authorization, so clients must be configured with appropriate access.

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

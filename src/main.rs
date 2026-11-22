use app::IdentityApp;

mod app;
mod cli;
mod client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = IdentityApp::configured()?;
    cli::run(app).await
}

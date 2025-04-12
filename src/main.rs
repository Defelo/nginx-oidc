#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nginx_oidc::cli::main().await
}

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use openidconnect::reqwest;
use state::State;
use tokio::net::{TcpListener, UnixListener};
use tracing::info;

use crate::oidc::client::ClientMap;

mod cookie;
mod routes;
mod state;

pub async fn serve(
    listen_address: ListenAddress,
    cookie_secret: Option<&[u8]>,
    clients: ClientMap,
    http: reqwest::Client,
) -> anyhow::Result<()> {
    let router = routes::router().with_state(State::new(cookie_secret, clients, http));

    match listen_address {
        ListenAddress::Tcp(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("Failed to bind to {addr} (tcp)"))?;
            info!("Listening on {} (tcp)", listener.local_addr()?);
            axum::serve(listener, router).await?;
        }
        ListenAddress::Unix(path) => {
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            let listener = UnixListener::bind(&path)
                .with_context(|| format!("Failed to bind to {} (unix)", path.display()))?;
            info!("Listening on {} (unix)", path.display());
            axum::serve(listener, router).await?;
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum ListenAddress {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

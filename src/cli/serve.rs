use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use anyhow::{Context, anyhow};
use clap::Args;
use futures::{TryStreamExt, stream::FuturesUnordered};
use tracing::{debug, info};

use crate::{
    config, http,
    oidc::{client::ClientWithConfig, make_http_client},
};

#[derive(Debug, Args)]
pub struct ServeCommand {
    #[command(flatten)]
    listen_address: ListenAddress,

    /// Path of the config file
    #[arg(long)]
    config: Vec<PathBuf>,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct ListenAddress {
    /// Listen on a TCP socket
    #[arg(long)]
    tcp: Option<SocketAddr>,

    /// Listen on a unix socket
    #[arg(long)]
    unix: Option<PathBuf>,
}

impl ServeCommand {
    pub async fn invoke(self) -> anyhow::Result<()> {
        info!("Loading config");
        let config = config::load(self.config.into_iter().map(Into::into))?;
        debug!("Config loaded: {config:?}");

        let http = make_http_client(config.ca_certs).context("Failed to build http client")?;

        info!("Loading clients");
        let clients = config
            .clients
            .into_iter()
            .map(|(key, value)| async {
                anyhow::Ok((key, ClientWithConfig::from_config(value, &http).await?))
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect::<HashMap<_, _>>()
            .await?;
        debug!("Clients loaded: {clients:?}");

        http::serve(
            self.listen_address.try_into()?,
            config.cookie_secret.as_deref(),
            clients,
            http,
        )
        .await
    }
}

impl TryFrom<ListenAddress> for http::ListenAddress {
    type Error = anyhow::Error;

    fn try_from(value: ListenAddress) -> Result<Self, Self::Error> {
        value
            .tcp
            .map(Self::Tcp)
            .or(value.unix.map(Self::Unix))
            .ok_or_else(|| anyhow!("no listen address selected"))
    }
}

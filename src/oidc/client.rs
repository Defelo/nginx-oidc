use std::collections::HashMap;

use openidconnect::{
    EndpointMaybeSet, EndpointNotSet, EndpointSet,
    core::{CoreClient, CoreProviderMetadata},
    reqwest,
};

use crate::config::ClientConfig;

pub type ClientMap = HashMap<String, ClientWithConfig>;

#[derive(Debug)]
pub struct ClientWithConfig {
    pub client: OidcClient,
    pub config: ClientConfig,
}

impl ClientWithConfig {
    pub async fn from_config(config: ClientConfig, http: &reqwest::Client) -> anyhow::Result<Self> {
        let provider_metadata =
            CoreProviderMetadata::discover_async(config.issuer.clone(), http).await?;
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            config.client_id.clone(),
            config.client_secret.clone(),
        );
        Ok(Self { client, config })
    }
}

pub type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

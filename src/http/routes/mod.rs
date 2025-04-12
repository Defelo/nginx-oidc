use std::net::IpAddr;

use anyhow::{Context, anyhow};
use axum::{Router, http::HeaderMap, routing::get};

use super::state::State;
use crate::config::ClientConfig;

mod auth;
mod callback;

pub fn router() -> Router<State> {
    Router::new()
        .route("/auth/{client_id}", get(auth::route))
        .route("/callback/{client_id}", get(callback::route))
}

fn get_ip(headers: &HeaderMap, client_config: &ClientConfig) -> anyhow::Result<Option<IpAddr>> {
    let Some(header) = client_config.real_ip_header.as_ref() else {
        return Ok(None);
    };

    get_header(headers, header)?
        .parse()
        .with_context(|| format!("failed to read '{header}' header"))
        .map(Some)
        .with_context(|| format!("failed to parse ip address from '{header}' header"))
}

fn get_header<'a>(headers: &'a HeaderMap, name: &str) -> anyhow::Result<&'a str> {
    headers
        .get(name)
        .ok_or_else(|| anyhow!("header not found"))?
        .to_str()
        .context("header contains invalid characters")
}

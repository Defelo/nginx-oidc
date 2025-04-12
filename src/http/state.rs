use std::{collections::HashMap, convert::Infallible, sync::Arc};

use axum::extract::{FromRef, FromRequestParts};
use axum_extra::extract::cookie::Key;
use openidconnect::reqwest;

use crate::oidc::client::ClientWithConfig;

#[derive(Debug, Clone)]
pub struct State {
    cookie_key: Key,
    pub clients: Arc<HashMap<String, ClientWithConfig>>,
    pub http: reqwest::Client,
}

impl State {
    pub fn new(
        cookie_secret: Option<&[u8]>,
        clients: HashMap<String, ClientWithConfig>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            cookie_key: cookie_secret
                .map(Key::derive_from)
                .unwrap_or_else(Key::generate),
            clients: clients.into(),
            http,
        }
    }
}

impl FromRequestParts<State> for State {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &State,
    ) -> Result<Self, Self::Rejection> {
        Ok(state.clone())
    }
}

impl FromRef<State> for Key {
    fn from_ref(input: &State) -> Self {
        input.cookie_key.clone()
    }
}

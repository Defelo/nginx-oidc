use std::time::SystemTime;

use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::PrivateCookieJar;
use openidconnect::{AuthorizationCode, CsrfToken};
use serde::Deserialize;
use tracing::error;

use super::get_ip;
use crate::{
    http::{
        cookie::{AuthCookie, SessionCookie, get_cookie, make_cookie},
        state::State,
    },
    oidc::{token::exchange_code, userinfo::get_userinfo},
    utils::UrlExt,
};

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: AuthorizationCode,
    state: CsrfToken,
}

pub async fn route(
    state: State,
    Path(client_id): Path<String>,
    Query(query): Query<CallbackQuery>,
    cookies: PrivateCookieJar,
    headers: HeaderMap,
) -> Response {
    let Some(client) = state.clients.get(&client_id) else {
        error!("client '{client_id}' not found");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let Ok(ip) = get_ip(&headers, &client.config)
        .inspect_err(|err| error!("failed to get user's real ip: {err:#}"))
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let Some(cookie) = get_cookie::<AuthCookie>(&cookies, &client_id, ip).filter(|c| {
        SystemTime::now()
            .duration_since(c.issued_at)
            .is_ok_and(|d| d < client.config.auth_cookie_ttl)
    }) else {
        return (StatusCode::BAD_REQUEST, "oidc cookie is missing or invalid").into_response();
    };

    let original_url = cookie.original_url;

    if query.state != cookie.auth_state.csrf_token {
        return (StatusCode::BAD_REQUEST, "csrf token mismatch").into_response();
    }

    let tokens = match exchange_code(client, cookie.auth_state, &state.http, query.code).await {
        Ok(Some(token_response)) => token_response,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "invalid authorization code").into_response();
        }
        Err(err) => {
            error!("failed to exchange authorization code: {err:#}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let Ok(userinfo) = get_userinfo(tokens.access_token.clone(), client, &state.http, tokens.sub)
        .await
        .inspect_err(|err| error!("failed to get userinfo: {err:#}"))
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let cookie = SessionCookie {
        issued_at: SystemTime::now(),
        userinfo,
        access_token: Some(tokens.access_token).filter(|_| client.config.keep_access_token),
        refresh_token: tokens
            .refresh_token
            .filter(|_| client.config.keep_refresh_token),
    };
    let Ok(cookie) =
        make_cookie(&client_id, ip, cookie, original_url.is_secure()).inspect_err(|err| {
            error!("failed to serialize session cookie: {err:#}");
        })
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    (
        cookies.add(cookie),
        Redirect::temporary(original_url.as_str()),
    )
        .into_response()
}

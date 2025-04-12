use std::{net::IpAddr, time::SystemTime};

use anyhow::Context as _;
use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use openidconnect::{reqwest, url::Url};
use serde::Deserialize;
use tracing::{debug, error};

use super::{get_header, get_ip};
use crate::{
    http::{
        cookie::{AuthCookie, SessionCookie, get_cookie, make_cookie},
        state::State,
    },
    oidc::{
        auth::make_auth_url,
        client::ClientWithConfig,
        token::refresh,
        userinfo::{UserInfo, get_userinfo},
    },
    utils::UrlExt,
};

#[derive(Debug, Deserialize)]
pub struct AuthQuery {
    role: Option<String>,
}

pub async fn route(
    state: State,
    Path(client_id): Path<String>,
    Query(query): Query<AuthQuery>,
    cookies: PrivateCookieJar,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let client = state.clients.get(&client_id).ok_or_else(|| {
        error!("client '{client_id}' not found");
        StatusCode::NOT_FOUND
    })?;

    let ip = get_ip(&headers, &client.config)
        .inspect_err(|err| error!("failed to get user's real ip: {err:#}"))
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let original_url = get_header(&headers, "x-original-url")
        .and_then(|x| Url::parse(x).context("header is not a valid url"))
        .inspect_err(|err| error!("failed to read x-original-url header: {err:#}"))
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let ctx = Context {
        client,
        http: &state.http,
        client_id,
        role: query.role,
        headers,
        original_url,
        ip,
    };

    if let Some(cookie) = get_cookie::<SessionCookie>(&cookies, &ctx.client_id, ip) {
        if SystemTime::now()
            .duration_since(cookie.issued_at)
            .is_ok_and(|d| d < client.config.session_cookie_ttl)
        {
            handle_valid_session(ctx, cookie)
        } else {
            handle_expired_session(ctx, cookies, cookie).await
        }
    } else {
        redirect_to_oidc_provider(ctx, cookies)
    }
}

struct Context<'a> {
    client: &'a ClientWithConfig,
    http: &'a reqwest::Client,
    client_id: String,
    role: Option<String>,
    headers: HeaderMap,
    original_url: Url,
    ip: Option<IpAddr>,
}

fn handle_valid_session(ctx: Context, cookie: SessionCookie) -> Result<Response, StatusCode> {
    let headers = make_auth_headers(&cookie.userinfo);

    let status = if ctx
        .role
        .is_none_or(|role| cookie.userinfo.roles.contains(&role))
    {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };

    Ok((status, headers).into_response())
}

fn make_auth_headers(userinfo: &UserInfo) -> HeaderMap {
    let mut headers = [
        ("x-auth-sub", Some(userinfo.sub.as_str())),
        ("x-auth-name", userinfo.name.as_ref().map(|s| s.as_str())),
        (
            "x-auth-username",
            userinfo.username.as_ref().map(|s| s.as_str()),
        ),
        ("x-auth-email", userinfo.email.as_ref().map(|s| s.as_str())),
    ]
    .into_iter()
    .filter_map(|(name, value)| Some((name.try_into().ok()?, value?.try_into().ok()?)))
    .collect::<HeaderMap>();

    if !userinfo.roles.is_empty() {
        if let Ok(roles) = userinfo.roles.join(" ").try_into() {
            headers.insert("x-auth-roles", roles);
        }
    }

    headers
}

async fn handle_expired_session(
    ctx: Context<'_>,
    cookies: PrivateCookieJar,
    mut cookie: SessionCookie,
) -> Result<Response, StatusCode> {
    let Some(access_token) = cookie.access_token.clone() else {
        debug!("reauthenticating due to missing access token");
        return redirect_to_oidc_provider(ctx, cookies);
    };

    debug!("trying to use cached access token");
    let userinfo = match get_userinfo(
        access_token,
        ctx.client,
        ctx.http,
        cookie.userinfo.sub.clone(),
    )
    .await
    {
        Ok(userinfo) => userinfo,
        Err(err) => {
            debug!("failed to get userinfo: {err:#}");

            let Some(refresh_token) = cookie.refresh_token.as_ref() else {
                debug!("reauthenticating due to missing refresh token");
                return redirect_to_oidc_provider(ctx, cookies);
            };

            let Ok(tokens) = refresh(refresh_token, ctx.client, ctx.http).await else {
                debug!("reauthenticating due to refresh failure");
                return redirect_to_oidc_provider(ctx, cookies);
            };

            cookie.access_token = Some(tokens.access_token.clone());
            cookie.refresh_token = tokens.refresh_token;
            get_userinfo(
                tokens.access_token,
                ctx.client,
                ctx.http,
                cookie.userinfo.sub,
            )
            .await
            .inspect_err(|err| error!("failed to get userinfo: {err:#}"))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
    };

    let cookie = SessionCookie {
        userinfo,
        issued_at: SystemTime::now(),
        ..cookie
    };
    let cookies = cookies.add(
        make_cookie(
            &ctx.client_id,
            ctx.ip,
            cookie.clone(),
            ctx.original_url.is_secure(),
        )
        .inspect_err(|err| {
            error!("failed to serialize auth cookie: {err:#}");
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    let response = handle_valid_session(ctx, cookie)?;

    Ok((cookies, response).into_response())
}

fn redirect_to_oidc_provider(
    ctx: Context,
    cookies: PrivateCookieJar,
) -> Result<Response, StatusCode> {
    let callback_path = get_header(&ctx.headers, "x-callback-path")
        .inspect_err(|err| error!("failed to read x-callback-path header: {err:#}"))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let callback_url = ctx
        .original_url
        .join(callback_path)
        .inspect_err(|err| error!("failed to construct callback url: {err:#}"))
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let (auth_url, auth_state) = make_auth_url(ctx.client, callback_url);

    let is_secure = ctx.original_url.is_secure();
    let cookie = AuthCookie {
        original_url: ctx.original_url,
        issued_at: SystemTime::now(),
        auth_state,
    };
    let mut cookie = make_cookie(&ctx.client_id, ctx.ip, cookie, is_secure)
        .inspect_err(|err| {
            error!("failed to serialize auth cookie: {err:#}");
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    cookie.set_max_age(Some(
        ctx.client
            .config
            .auth_cookie_ttl
            .try_into()
            .inspect_err(|err| error!("Failed to convert auth_cookie_ttl: {err:#}"))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ));

    Ok((
        StatusCode::UNAUTHORIZED,
        [("x-auth-redirect", auth_url.as_str())],
        cookies.add(cookie),
    )
        .into_response())
}

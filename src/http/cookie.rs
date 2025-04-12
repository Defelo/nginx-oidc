use std::{borrow::Cow, net::IpAddr, time::SystemTime};

use axum_extra::extract::{
    PrivateCookieJar,
    cookie::{Cookie, SameSite},
};
use openidconnect::{AccessToken, RefreshToken, url::Url};
use serde::{Deserialize, Serialize};

use crate::oidc::{auth::AuthState, userinfo::UserInfo};

#[derive(Debug, Serialize, Deserialize)]
struct CookieWrapper<'a> {
    client_id: Cow<'a, str>,
    ip: Option<IpAddr>,
    data: CookieData,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CookieData {
    Auth(AuthCookie),
    Session(SessionCookie),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCookie {
    pub issued_at: SystemTime,
    pub original_url: Url,
    pub auth_state: AuthState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCookie {
    pub issued_at: SystemTime,
    pub userinfo: UserInfo,
    pub access_token: Option<AccessToken>,
    pub refresh_token: Option<RefreshToken>,
}

fn cookie_name(client_id: &str) -> String {
    format!("_nginx_oidc_{client_id}")
}

pub fn get_cookie<C: TryFrom<CookieData>>(
    jar: &PrivateCookieJar,
    client_id: &str,
    ip: Option<IpAddr>,
) -> Option<C> {
    serde_json::from_str::<CookieWrapper>(jar.get(&cookie_name(client_id))?.value())
        .ok()
        .and_then(|c| (c.client_id == client_id && c.ip == ip).then_some(c.data))?
        .try_into()
        .ok()
}

pub fn make_cookie(
    client_id: &str,
    ip: Option<IpAddr>,
    value: impl Into<CookieData>,
    secure: bool,
) -> anyhow::Result<Cookie<'static>> {
    let mut cookie = Cookie::new(
        cookie_name(client_id),
        serde_json::to_string(&CookieWrapper {
            client_id: client_id.into(),
            ip,
            data: value.into(),
        })?,
    );
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(secure);
    cookie.set_same_site(SameSite::Strict);
    Ok(cookie)
}

impl TryFrom<CookieData> for AuthCookie {
    type Error = ();
    fn try_from(value: CookieData) -> Result<Self, Self::Error> {
        match value {
            CookieData::Auth(auth_cookie) => Ok(auth_cookie),
            _ => Err(()),
        }
    }
}

impl TryFrom<CookieData> for SessionCookie {
    type Error = ();
    fn try_from(value: CookieData) -> Result<Self, Self::Error> {
        match value {
            CookieData::Session(session_cookie) => Ok(session_cookie),
            _ => Err(()),
        }
    }
}

impl From<AuthCookie> for CookieData {
    fn from(value: AuthCookie) -> Self {
        Self::Auth(value)
    }
}

impl From<SessionCookie> for CookieData {
    fn from(value: SessionCookie) -> Self {
        Self::Session(value)
    }
}

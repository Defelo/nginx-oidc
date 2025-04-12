use std::borrow::Cow;

use anyhow::{anyhow, ensure};
use openidconnect::{
    AccessToken, AccessTokenHash, AuthorizationCode, OAuth2TokenResponse, RefreshToken,
    RequestTokenError, SubjectIdentifier, TokenResponse, reqwest,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{auth::AuthState, client::ClientWithConfig};

pub async fn exchange_code(
    client: &ClientWithConfig,
    auth_state: AuthState,
    http: &reqwest::Client,
    code: AuthorizationCode,
) -> anyhow::Result<Option<OidcTokens>> {
    let token_response = match client
        .client
        .exchange_code(code)?
        .set_pkce_verifier(auth_state.pkce_verifier)
        .set_redirect_uri(Cow::Borrowed(&auth_state.callback_url))
        .request_async(http)
        .await
    {
        Ok(token_response) => token_response,
        Err(RequestTokenError::ServerResponse(err)) => {
            debug!("failed to exchange authorization code: {err:#}");
            return Ok(None);
        }
        Err(err) => return Err(err.into()),
    };

    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("server did not return an id token"))?;
    let id_token_verifier = client.client.id_token_verifier();
    let claims = id_token.claims(&id_token_verifier, &auth_state.nonce)?;

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token.signing_alg()?,
            id_token.signing_key(&id_token_verifier)?,
        )?;
        ensure!(
            actual_access_token_hash == *expected_access_token_hash,
            "invalid access token"
        );
    }

    Ok(Some(OidcTokens {
        access_token: token_response.access_token().clone(),
        refresh_token: token_response.refresh_token().cloned(),
        sub: claims.subject().clone(),
    }))
}

pub async fn refresh(
    refresh_token: &RefreshToken,
    client: &ClientWithConfig,
    http: &reqwest::Client,
) -> anyhow::Result<OidcTokens> {
    let response = client
        .client
        .exchange_refresh_token(refresh_token)?
        .request_async(http)
        .await?;

    let id_token = response
        .id_token()
        .ok_or_else(|| anyhow!("server did not return an id token"))?;
    let id_token_verifier = client.client.id_token_verifier();
    let claims = id_token.claims(&id_token_verifier, |_: Option<&_>| Ok(()))?;

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            response.access_token(),
            id_token.signing_alg()?,
            id_token.signing_key(&id_token_verifier)?,
        )?;
        ensure!(
            actual_access_token_hash == *expected_access_token_hash,
            "invalid access token"
        );
    }

    Ok(OidcTokens {
        access_token: response.access_token().clone(),
        refresh_token: response.refresh_token().cloned(),
        sub: claims.subject().clone(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokens {
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    pub sub: SubjectIdentifier,
}

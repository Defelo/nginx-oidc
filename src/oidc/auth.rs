use std::borrow::Cow;

use openidconnect::{
    CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    core::CoreAuthenticationFlow, url::Url,
};
use serde::{Deserialize, Serialize};

use super::client::ClientWithConfig;

pub fn make_auth_url(client: &ClientWithConfig, callback_url: Url) -> (Url, AuthState) {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let callback_url = RedirectUrl::from_url(callback_url);

    let (auth_url, csrf_token, nonce) = client
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(client.config.scopes.iter().cloned())
        .set_pkce_challenge(pkce_challenge)
        .set_redirect_uri(Cow::Borrowed(&callback_url))
        .url();

    let auth_state = AuthState {
        callback_url,
        pkce_verifier,
        csrf_token,
        nonce,
    };

    (auth_url, auth_state)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthState {
    pub callback_url: RedirectUrl,
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
    pub nonce: Nonce,
}

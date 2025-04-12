use openidconnect::{
    AccessToken, EndUserEmail, EndUserName, EndUserUsername, SubjectIdentifier, UserInfoClaims,
    core::CoreGenderClaim, reqwest,
};
use serde::{Deserialize, Serialize};

use super::{client::ClientWithConfig, custom_claims::CustomClaims};

pub async fn get_userinfo(
    access_token: AccessToken,
    client: &ClientWithConfig,
    http: &reqwest::Client,
    expected_sub: SubjectIdentifier,
) -> anyhow::Result<UserInfo> {
    let claims: UserInfoClaims<CustomClaims, CoreGenderClaim> = client
        .client
        .user_info(access_token, Some(expected_sub))?
        .request_async(http)
        .await?;

    let roles = client
        .config
        .roles_claim
        .as_ref()
        .and_then(|claim| claims.additional_claims().get(claim))
        .and_then(|claim| claim.as_array())
        .iter()
        .flat_map(|&roles| roles)
        .filter_map(|role| role.as_str())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    Ok(UserInfo {
        sub: claims.subject().clone(),
        name: claims
            .name()
            .and_then(|name| name.iter().next())
            .map(|(_, name)| name.clone()),
        username: claims.preferred_username().cloned(),
        email: claims.email().cloned(),
        roles,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: SubjectIdentifier,
    pub name: Option<EndUserName>,
    pub username: Option<EndUserUsername>,
    pub email: Option<EndUserEmail>,
    pub roles: Vec<String>,
}

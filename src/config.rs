use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, ensure};
use config::{File, FileFormat};
use openidconnect::{ClientId, ClientSecret, IssuerUrl, Scope};

pub fn load<'a>(config_path: impl IntoIterator<Item = Cow<'a, Path>>) -> anyhow::Result<Config> {
    load_with_defaults([], config_path)
}

fn load_with_defaults<'a>(
    defaults: impl IntoIterator<Item = Cow<'a, str>>,
    config_path: impl IntoIterator<Item = Cow<'a, Path>>,
) -> anyhow::Result<Config> {
    defaults
        .into_iter()
        .chain([include_str!("../config.yml").into()])
        .map(Ok)
        .chain(
            config_path
                .into_iter()
                .map(|path| std::fs::read_to_string(path).map(Into::into)),
        )
        .map(|content| content.map(|content| File::from_str(&content, FileFormat::Yaml)))
        .try_fold(config::Config::builder(), |builder, source| {
            anyhow::Ok(builder.add_source(source?))
        })?
        .build()
        .context("Failed to read config file")?
        .try_deserialize::<raw::Config>()
        .context("Failed to deserialize config")?
        .try_into()
        .context("Failed to load config")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub cookie_secret: Option<Vec<u8>>,
    pub ca_certs: Vec<PathBuf>,
    pub clients: HashMap<String, ClientConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub issuer: IssuerUrl,
    pub client_id: ClientId,
    pub client_secret: Option<ClientSecret>,
    pub scopes: Vec<Scope>,
    pub roles_claim: Option<String>,
    pub auth_cookie_ttl: Duration,
    pub session_cookie_ttl: Duration,
    pub keep_access_token: bool,
    pub keep_refresh_token: bool,
    pub real_ip_header: Option<String>,
}

impl TryFrom<raw::Config> for Config {
    type Error = anyhow::Error;
    fn try_from(value: raw::Config) -> anyhow::Result<Self> {
        let cookie_secret = value
            .cookie_secret_path
            .map(|path| {
                std::fs::read(&path)
                    .with_context(|| format!("Failed to read file '{}'", path.display()))
            })
            .transpose()?;
        ensure!(
            cookie_secret.as_ref().is_none_or(|c| c.len() >= 32),
            "cookie secret is too short (min. 32 bytes)"
        );

        Ok(Self {
            cookie_secret,
            ca_certs: value.ca_certs,
            clients: value
                .clients
                .into_iter()
                .map(|(key, value)| {
                    anyhow::Ok((
                        key.clone(),
                        ClientConfig::try_from_raw(key.clone(), value)
                            .with_context(|| format!("Failed to load client '{key}'"))?,
                    ))
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

impl ClientConfig {
    fn try_from_raw(key: String, value: raw::ClientConfig) -> anyhow::Result<Self> {
        Ok(Self {
            issuer: value.issuer,
            client_id: value.client_id.unwrap_or_else(|| ClientId::new(key)),
            client_secret: value
                .client_secret_path
                .map(|path| {
                    std::fs::read_to_string(&path)
                        .map(ClientSecret::new)
                        .with_context(|| format!("Failed to read file '{}'", path.display()))
                })
                .transpose()?,
            scopes: value.scopes,
            roles_claim: value.roles_claim,
            auth_cookie_ttl: Duration::from_secs(value.auth_cookie_ttl_secs),
            session_cookie_ttl: Duration::from_secs(value.session_cookie_ttl_secs),
            keep_access_token: value.keep_access_token,
            keep_refresh_token: value.keep_refresh_token,
            real_ip_header: value.real_ip_header,
        })
    }
}

mod raw {
    use std::{collections::HashMap, path::PathBuf};

    use openidconnect::{ClientId, IssuerUrl, Scope};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub cookie_secret_path: Option<PathBuf>,
        pub ca_certs: Vec<PathBuf>,
        pub clients: HashMap<String, ClientConfig>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ClientConfig {
        pub issuer: IssuerUrl,
        pub client_id: Option<ClientId>,
        pub client_secret_path: Option<PathBuf>,
        pub scopes: Vec<Scope>,
        pub roles_claim: Option<String>,
        pub auth_cookie_ttl_secs: u64,
        pub session_cookie_ttl_secs: u64,
        pub keep_access_token: bool,
        pub keep_refresh_token: bool,
        pub real_ip_header: Option<String>,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Write;

    use pretty_assertions::assert_eq;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn load() {
        let secrets = setup_secrets();
        let expected = Config {
            cookie_secret: Some(b"super-secure-and-definitely-random-cookie-secret".into()),
            ca_certs: vec![],
            clients: [(
                "test".into(),
                ClientConfig {
                    issuer: IssuerUrl::new(
                        "https://id.example.com/oauth2/openid/test-client".into(),
                    )
                    .unwrap(),
                    client_id: ClientId::new("test-client-id".into()),
                    client_secret: Some(ClientSecret::new("test-client-secret-123".into())),
                    scopes: vec![Scope::new("test".into())],
                    roles_claim: Some("test-roles".into()),
                    auth_cookie_ttl: Duration::from_secs(42),
                    session_cookie_ttl: Duration::from_secs(1337),
                    keep_access_token: false,
                    keep_refresh_token: false,
                    real_ip_header: Some("X-Real-Ip".into()),
                },
            )]
            .into(),
        };

        let cookie_secret_path = secrets.cookie.path().display();
        let test_client_secret_path = secrets.test_client.path().display();
        let defaults = format!(
            r#"
cookie_secret_path: "{cookie_secret_path}"
clients:
    test:
        issuer: "https://id.example.com/oauth2/openid/test-client"
        client_id: "test-client-id"
        client_secret_path: "{test_client_secret_path}"
        scopes: [ "test" ]
        roles_claim: "test-roles"
        auth_cookie_ttl_secs: 42
        session_cookie_ttl_secs: 1337
        keep_access_token: false
        keep_refresh_token: false
        real_ip_header: "X-Real-Ip"
            "#
        );

        let config = load_with_defaults([&defaults].map(Into::into), []).unwrap();

        assert_eq!(config, expected);
    }

    struct Secrets {
        cookie: NamedTempFile,
        test_client: NamedTempFile,
    }

    fn setup_secrets() -> Secrets {
        let mut secrets = Secrets {
            cookie: NamedTempFile::new().unwrap(),
            test_client: NamedTempFile::new().unwrap(),
        };
        write!(
            &mut secrets.cookie,
            "super-secure-and-definitely-random-cookie-secret"
        )
        .unwrap();
        write!(&mut secrets.test_client, "test-client-secret-123").unwrap();
        secrets
    }
}

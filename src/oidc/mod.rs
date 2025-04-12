use std::path::Path;

use anyhow::Context;
use openidconnect::reqwest::{self, Certificate};
use tracing::warn;

pub mod auth;
pub mod client;
mod custom_claims;
pub mod token;
pub mod userinfo;

pub fn make_http_client(
    ca_certs: impl IntoIterator<Item = impl AsRef<Path>>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls();

    for cert_path in ca_certs {
        let cert_path = cert_path.as_ref();
        warn!("Trusting certificates in {}", cert_path.display());
        let content = std::fs::read(cert_path)
            .with_context(|| format!("Failed to read file at {}", cert_path.display()))?;
        let certs = Certificate::from_pem_bundle(&content).with_context(|| {
            format!(
                "Failed to read CA certificates from {}",
                cert_path.display()
            )
        })?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    builder.build().map_err(Into::into)
}

use openidconnect::url::Url;

pub trait UrlExt {
    fn is_secure(&self) -> bool;
}

impl UrlExt for Url {
    fn is_secure(&self) -> bool {
        self.scheme() == "https"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn is_secure() {
        assert!(Url::parse("https://example.com/").unwrap().is_secure());
        assert!(!Url::parse("http://example.com/").unwrap().is_secure());
    }
}

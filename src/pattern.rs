use std::str::FromStr;

use itertools::{EitherOrBoth, Itertools};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Pattern {
    host: Vec<glob::Pattern>,
    port: Option<u16>,
    path: String,
}

impl Pattern {
    pub fn matches(&self, image: &Url) -> bool {
        let Some(host) = image.host_str() else {
            return false;
        };
        let host_matches = self
            .host
            .iter()
            .zip_longest(host.split('.'))
            .all(|z| match z {
                EitherOrBoth::Both(pattern, image) => pattern.matches(image),
                _ => false,
            });

        host_matches && image.port() == self.port && image.path().starts_with(&self.path)
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid URL")]
    InvalidUrl(#[from] url::ParseError),
    #[error("invalid URL glob component")]
    InvalidGlob(#[from] glob::PatternError),
    #[error("missing host in URL")]
    NoHost,
}

impl FromStr for Pattern {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(&format!("https://{}", s))?;
        let host = match url.host() {
            Some(url::Host::Domain(domain)) => domain
                .split(".")
                .map(glob::Pattern::new)
                .collect::<Result<_, _>>()?,
            Some(url::Host::Ipv4(addr)) => vec![glob::Pattern::new(&glob::Pattern::escape(
                &addr.to_string(),
            ))?],
            Some(url::Host::Ipv6(addr)) => vec![glob::Pattern::new(&glob::Pattern::escape(
                &addr.to_string(),
            ))?],
            None => Err(ParseError::NoHost)?,
        };
        Ok(Pattern {
            host,
            port: url.port(),
            path: url.path().to_owned(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_patterns(components: &[&str]) -> Vec<glob::Pattern> {
        components
            .iter()
            .map(|s| glob::Pattern::new(s))
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn test_parse() {
        let pattern = Pattern::from_str("foo.example.com").unwrap();
        assert_eq!(pattern.host, make_patterns(&["foo", "example", "com"]));
        assert_eq!(pattern.port, None);
        assert_eq!(pattern.path, "/");

        let pattern = Pattern::from_str("*.example.com").unwrap();
        assert_eq!(pattern.host, make_patterns(&["*", "example", "com"]));
        let pattern = Pattern::from_str("example.*").unwrap();
        assert_eq!(pattern.host, make_patterns(&["example", "*"]));
        let pattern = Pattern::from_str("foo*.example.com").unwrap();
        assert_eq!(pattern.host, make_patterns(&["foo*", "example", "com"]));

        let pattern = Pattern::from_str("example.com:8080").unwrap();
        assert_eq!(pattern.port, Some(8080));
        let pattern = Pattern::from_str("example.com:8080/xy").unwrap();
        assert_eq!(pattern.path, "/xy");

        let pattern = Pattern::from_str("192.0.2.1").unwrap();
        assert_eq!(
            pattern.host,
            vec![glob::Pattern::new(&glob::Pattern::escape("192.0.2.1")).unwrap()]
        );
        let pattern = Pattern::from_str("[2001:db8:123::456]").unwrap();
        assert_eq!(
            pattern.host,
            vec![glob::Pattern::new(&glob::Pattern::escape("2001:db8:123::456")).unwrap()]
        );
        assert!(Pattern::from_str("192.*.2.1").is_err());
        assert!(Pattern::from_str("[2001:db8:*::456]").is_err());
    }

    #[test]
    fn test_match() {
        let pattern = Pattern::from_str("foo.example.com").unwrap();
        assert!(pattern.matches(&Url::parse("http://foo.example.com").unwrap()));
        assert!(pattern.matches(&Url::parse("http://foo.example.com/bar").unwrap()));
        assert!(!pattern.matches(&Url::parse("http://bar.example.com").unwrap()));
        assert!(!pattern.matches(&Url::parse("http://foo.example.com:8080").unwrap()));

        let pattern = Pattern::from_str("foo.example.com:8080").unwrap();
        assert!(pattern.matches(&Url::parse("http://foo.example.com:8080").unwrap()));
        assert!(!pattern.matches(&Url::parse("http://foo.example.com").unwrap()));

        let pattern = Pattern::from_str("foo.example.com:8080/bar/baz").unwrap();
        assert!(!pattern.matches(&Url::parse("http://foo.example.com:8080").unwrap()));
        assert!(!pattern.matches(&Url::parse("http://foo.example.com").unwrap()));
        assert!(!pattern.matches(&Url::parse("http://foo.example.com:8080/bar/ba").unwrap()));
        assert!(pattern.matches(&Url::parse("http://foo.example.com:8080/bar/baz").unwrap()));
        assert!(pattern.matches(&Url::parse("http://foo.example.com:8080/bar/bazz").unwrap()));
        assert!(pattern.matches(&Url::parse("http://foo.example.com:8080/bar/baz/qux").unwrap()));
    }
}

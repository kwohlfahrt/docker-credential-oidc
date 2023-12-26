use std::collections::HashMap;

use reqwest::{StatusCode, Url};
use serde::Deserialize;

#[derive(Debug)]
pub struct AuthInfo {
    pub service: String,
    openid_configuration: OpenIdConfiguration,
}

#[derive(Deserialize, Debug)]
struct OpenIdConfiguration {
    authorization_endpoint: String,
    token_endpoint: String,
}

impl AuthInfo {
    pub fn for_image(client: &reqwest::blocking::Client, image: &str) -> Self {
        if let Some((registry, _)) = image.split_once('/') {
            Self::for_registry(client, registry)
        } else {
            Self::for_registry(client, image)
        }
    }

    pub fn for_registry(client: &reqwest::blocking::Client, registry: &str) -> Self {
        let resp = client
            .get(format!("https://{}/v2/", registry))
            .send()
            .unwrap();

        let auth = match resp.status() {
            StatusCode::UNAUTHORIZED => resp.headers().get("www-authenticate").unwrap(),
            _ => panic!("Expected 401 response, got {}", resp.status()),
        };

        let challenges = auth
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap()
            .split(",")
            .map(|c| {
                let (k, v) = c.split_once("=").unwrap();
                (k, v.trim_matches('"'))
            })
            .collect::<HashMap<_, _>>();

        let realm = challenges.get("realm").unwrap().to_string();
        let openid_configuration = Self::openid_configuration(&client, &realm);

        AuthInfo {
            service: challenges.get("service").unwrap().to_string(),
            openid_configuration: openid_configuration,
        }
    }

    fn openid_configuration(
        client: &reqwest::blocking::Client,
        realm: &str,
    ) -> OpenIdConfiguration {
        let (path, _) = realm.rsplit_once('/').unwrap();
        let mut url = Url::parse(path).unwrap();
        url.set_path(&format!(
            "{}/{}",
            url.path(),
            ".well-known/openid-configuration"
        ));
        client.get(url).send().unwrap().json().unwrap()
    }

    pub fn auth_url(&self) -> Url {
        Url::parse(&self.openid_configuration.authorization_endpoint).unwrap()
    }

    pub fn token_url(&self) -> Url {
        // TODO: Cache openid_configuration
        Url::parse(&self.openid_configuration.token_endpoint).unwrap()
    }
}

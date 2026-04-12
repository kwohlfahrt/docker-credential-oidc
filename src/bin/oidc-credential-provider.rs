use std::{
    collections::HashMap,
    env,
    io::{self, Error},
};

use clap::Parser;
use oauth2::{AccessToken, ClientId, ClientSecret, TokenResponse};
use serde::{Deserialize, Serialize};

use docker_credential_oidc::{pattern, AuthInfo};
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
enum ApiVersion {
    #[serde(rename = "credentialprovider.kubelet.k8s.io/v1")]
    V1,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", tag = "kind")]
struct CredentialProviderRequest {
    #[allow(dead_code)]
    api_version: ApiVersion,
    image: String,
}

#[derive(Serialize, Debug)]
enum CacheKeyType {
    #[allow(dead_code)]
    Image,
    Registry,
    #[allow(dead_code)]
    Global,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AuthConfig {
    username: String,
    password: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase", tag = "kind")]
struct CredentialProviderResponse {
    api_version: ApiVersion,
    cache_key_type: CacheKeyType,
    auth: Option<HashMap<String, AuthConfig>>,
}

fn auth(client_id: ClientId, auth_info: &AuthInfo) -> AccessToken {
    const SECRET_ENV_VAR: &str = "OIDC_CLIENT_SECRET";
    let secret =
        env::var(SECRET_ENV_VAR).expect(&format!("environment variable {}", SECRET_ENV_VAR));

    let client = oauth2::basic::BasicClient::new(
        client_id,
        Some(ClientSecret::new(secret)),
        auth_info.auth_url(),
        Some(auth_info.token_url()),
    );

    let access = client
        .exchange_client_credentials()
        .request(oauth2::reqwest::http_client)
        .unwrap();

    access.access_token().to_owned()
}

#[derive(Parser)]
struct Args {
    #[arg(num_args=0..)]
    clients: Vec<ClientRegistries>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ClientRegistries {
    client: ClientId,
    registries: Vec<pattern::Pattern>,
}

impl ClientRegistries {
    fn matches(&self, image: &Url) -> bool {
        self.registries.iter().any(|p| p.matches(image))
    }
}

impl std::str::FromStr for ClientRegistries {
    type Err = pattern::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (client, registries) = s.split_once(':').unwrap_or((s, ""));
        let registries = registries
            .split(',')
            .map(pattern::Pattern::from_str)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            client: ClientId::new(client.to_owned()),
            registries,
        })
    }
}

fn get_credentials(
    client: ClientId,
    request: &CredentialProviderRequest,
) -> HashMap<String, AuthConfig> {
    let http_client = reqwest::blocking::Client::new();
    let auth_info = AuthInfo::for_image(&http_client, &request.image);

    let token = auth(client, &auth_info);
    HashMap::from([(
        auth_info.service,
        AuthConfig {
            username: "OIDC".to_owned(),
            password: token.secret().to_string(),
        },
    )])
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    let request: CredentialProviderRequest = serde_json::from_reader(io::stdin())?;
    let url = Url::parse(&format!("https://{}", request.image));
    let auth = args
        .clients
        .into_iter()
        .find(|c| url.as_ref().is_ok_and(|u| c.matches(u)))
        .map(|client| get_credentials(client.client, &request));

    serde_json::to_writer(
        io::stdout(),
        &CredentialProviderResponse {
            api_version: ApiVersion::V1,
            cache_key_type: CacheKeyType::Registry,
            auth,
        },
    )?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_parse_args() {
        let args = Args::try_parse_from(vec![
            "oidc-credential-provider",
            "foo@example.com:foo.example.com,*.foo.example.com",
            "bar@example.com:registry.bar.example.com",
        ])
        .unwrap();

        let expected = vec![
            ClientRegistries {
                client: ClientId::new("foo@example.com".to_owned()),
                registries: vec![
                    pattern::Pattern::from_str("foo.example.com").unwrap(),
                    pattern::Pattern::from_str("*.foo.example.com").unwrap(),
                ],
            },
            ClientRegistries {
                client: ClientId::new("bar@example.com".to_owned()),
                registries: vec![pattern::Pattern::from_str("registry.bar.example.com").unwrap()],
            },
        ];

        assert_eq!(args.clients, expected);
    }
}

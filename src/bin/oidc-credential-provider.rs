use std::{
    collections::HashMap,
    env,
    io::{self, Error},
};

use clap::Parser;
use oauth2::{AccessToken, ClientId, ClientSecret, TokenResponse};
use serde::{Deserialize, Serialize};

use docker_credential_oidc::AuthInfo;

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
    client_id: String,
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    let request: CredentialProviderRequest = serde_json::from_reader(io::stdin())?;
    let http_client = reqwest::blocking::Client::new();
    let auth_info = AuthInfo::for_image(&http_client, &request.image);

    let token = auth(ClientId::new(args.client_id), &auth_info);
    let output = CredentialProviderResponse {
        api_version: ApiVersion::V1,
        cache_key_type: CacheKeyType::Registry,
        auth: Some(HashMap::from([(
            auth_info.service,
            AuthConfig {
                username: "OIDC".to_owned(),
                password: token.secret().to_string(),
            },
        )])),
    };

    serde_json::to_writer(io::stdout(), &output)?;

    Ok(())
}

use std::{
    collections::HashMap,
    env,
    io::{self, Error},
};

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

const ENV_VAR_NAME: &str = "KUBERNETES_CREDENTIAL_OIDC_SECRET";

fn main() -> Result<(), Error> {
    let request: CredentialProviderRequest = serde_json::from_reader(io::stdin())?;
    let http_client = reqwest::blocking::Client::new();
    let auth_info = AuthInfo::for_image(&http_client, &request.image);

    let secret = env::var(ENV_VAR_NAME).expect(&format!("environment variable {}", ENV_VAR_NAME));

    let auth = [(
        auth_info.service,
        AuthConfig {
            username: "OIDC".to_owned(),
            password: "abcd".to_owned(),
        },
    )]
    .into_iter()
    .collect();

    let output = CredentialProviderResponse {
        api_version: ApiVersion::V1,
        cache_key_type: CacheKeyType::Registry,
        auth: Some(auth),
    };

    serde_json::to_writer(io::stdout(), &output)?;

    Ok(())
}

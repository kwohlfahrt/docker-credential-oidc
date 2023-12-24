use std::{collections::HashMap, io, sync::Arc};

use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use axum::{
    extract::{Query, State},
    response::Redirect,
    routing::get,
    Router,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Get {},
}

#[derive(Debug)]
struct AuthInfo {
    service: String,
    openid_configuration: OpenIdConfiguration,
}

#[derive(Deserialize, Debug)]
struct OpenIdConfiguration {
    authorization_endpoint: String,
    token_endpoint: String,
}

impl AuthInfo {
    async fn for_registry(client: &reqwest::Client, registry: &str) -> Self {
        let resp = client
            .get(format!("https://{}/v2/", registry))
            .send()
            .await
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
        let openid_configuration = Self::openid_configuration(&client, &realm).await;

        AuthInfo {
            service: challenges.get("service").unwrap().to_string(),
            openid_configuration: openid_configuration,
        }
    }

    async fn openid_configuration(client: &reqwest::Client, realm: &str) -> OpenIdConfiguration {
        let (path, _) = realm.rsplit_once('/').unwrap();
        let mut url = Url::parse(path).unwrap();
        url.set_path(&format!(
            "{}/{}",
            url.path(),
            ".well-known/openid-configuration"
        ));
        client.get(url).send().await.unwrap().json().await.unwrap()
    }

    fn auth_url(&self) -> Url {
        Url::parse(&self.openid_configuration.authorization_endpoint).unwrap()
    }

    fn token_url(&self) -> Url {
        // TODO: Cache openid_configuration
        Url::parse(&self.openid_configuration.token_endpoint).unwrap()
    }
}

#[derive(Debug)]
struct Auth {
    client: Client,
    info: AuthInfo,
    code_challenge: (PkceCodeChallenge, PkceCodeVerifier),
}

#[derive(Deserialize)]
struct Callback {
    code: String,
}

#[derive(Deserialize)]
struct Token {
    access_token: String,
}

#[derive(Serialize)]
struct Output {
    server_url: String,
    username: String,
    secret: String,
}

impl Auth {
    fn new(client: Client, info: AuthInfo) -> Self {
        return Auth {
            client: client,
            info: info,
            code_challenge: PkceCodeChallenge::new_random_sha256(),
        };
    }

    async fn start(&self) -> Redirect {
        let redirect = format!("http://localhost:8000/callback");

        let mut uri = self.info.auth_url();
        uri.query_pairs_mut()
            .clear()
            .append_pair("client_id", &self.info.service)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &redirect)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", self.code_challenge.0.as_str());

        Redirect::to(&uri.to_string())
    }

    async fn callback(&self, query: &Callback) -> String {
        let uri = self.info.token_url();
        let redirect = format!("http://localhost:8000/callback");

        let params: Vec<(&str, &str)> = vec![
            ("client_id", &self.info.service),
            ("code", &query.code),
            ("code_verifier", self.code_challenge.1.secret()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", &redirect),
        ];

        let resp: Token = self
            .client
            .post(uri)
            .form(&params)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        println!(
            "{{\"ServerURL\": \"{}\", \"Username\": \"OIDC\", \"Secret\": \"{}\" }}",
            self.info.service, resp.access_token
        );

        format!(
            "Successfully authenticated to {}! You may close this window.",
            self.info.service
        )
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    match args.command {
        Command::Get {} => {
            let mut registry = String::new();
            io::stdin().read_line(&mut registry).unwrap();
            let registry = registry.trim();

            let client = reqwest::Client::new();
            let auth_info = AuthInfo::for_registry(&client, registry).await;

            let app = Router::new()
                .route(
                    "/start",
                    get(move |State(state): State<Arc<Auth>>| async move {
                        state.as_ref().start().await
                    }),
                )
                .route(
                    "/callback",
                    get(
                        move |State(state): State<Arc<Auth>>, query: Query<Callback>| async move {
                            state.as_ref().callback(&query).await
                        },
                    ),
                )
                .with_state(Arc::new(Auth::new(client, auth_info)));
            let listener = TcpListener::bind("0.0.0.0:8000").await.unwrap();

            axum::serve(listener, app)
        }
    }
    .await
    .unwrap()
}

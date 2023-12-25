use std::{
    collections::HashMap,
    io::{self, Error},
};

use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, HttpResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, TokenResponse, TokenUrl,
};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};

use clap::{Parser, Subcommand};
use tiny_http::{Method, Response};

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
    fn for_registry(client: &reqwest::blocking::Client, registry: &str) -> Self {
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
    client: oauth2::basic::BasicClient,
    http_client: reqwest::blocking::Client,
    pkce_verifier: PkceCodeVerifier,
    service: String,
    csrf_token: CsrfToken,
}

#[derive(Deserialize, Debug)]
struct Callback {
    code: String,
    state: String,
}

#[derive(Serialize)]
struct Output<'a> {
    #[serde(rename = "ServerURL")]
    server_url: &'a str,
    #[serde(rename = "Username")]
    username: &'a str,
    #[serde(rename = "Secret")]
    secret: &'a str,
}

impl Auth {
    fn new(http_client: reqwest::blocking::Client, auth_info: &AuthInfo) -> Self {
        let client = oauth2::basic::BasicClient::new(
            ClientId::new(auth_info.service.to_owned()),
            None,
            AuthUrl::new(auth_info.auth_url().to_string()).unwrap(),
            Some(TokenUrl::new(auth_info.token_url().to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new("http://localhost:8000/callback".to_string()).unwrap());

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .url();

        webbrowser::open(&auth_url.to_string()).unwrap();

        return Auth {
            http_client,
            client,
            pkce_verifier,
            csrf_token,
            service: auth_info.service.to_owned(),
        };
    }

    fn callback(self, query: Callback) -> String {
        assert_eq!(self.csrf_token.secret(), &query.state);

        let token = self
            .client
            .exchange_code(AuthorizationCode::new(query.code))
            .set_pkce_verifier(self.pkce_verifier)
            .request(|r| {
                let resp = self
                    .http_client
                    .request(r.method, r.url)
                    .headers(r.headers)
                    .body(r.body)
                    .send()?;

                Ok::<_, reqwest::Error>(HttpResponse {
                    status_code: resp.status(),
                    headers: resp.headers().to_owned(),
                    body: resp.bytes()?.to_vec(),
                })
            })
            .unwrap();

        println!(
            "{}",
            serde_json::to_string(&Output {
                server_url: &self.service,
                username: "OIDC",
                secret: token.access_token().secret(),
            })
            .unwrap()
        );

        format!(
            "Successfully authenticated to {}! You may close this window.",
            self.service
        )
    }
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    match args.command {
        Command::Get {} => {
            let mut registry = String::new();
            io::stdin().read_line(&mut registry).unwrap();
            let registry = registry.trim();

            let http_client = reqwest::blocking::Client::new();
            let auth_info = AuthInfo::for_registry(&http_client, registry);
            let auth = Auth::new(http_client, &auth_info);

            let server = tiny_http::Server::http("localhost:8000").unwrap();
            let request = server.recv()?;

            assert_eq!(request.method(), &Method::Get);
            let url = Url::parse("http://localhost:8000")
                .unwrap()
                .join(request.url())
                .unwrap();
            assert_eq!(url.path(), "/callback");

            let query = url.query_pairs().collect::<HashMap<_, _>>();

            let response = auth.callback(Callback {
                code: query.get("code").unwrap().to_string(),
                state: query.get("state").unwrap().to_string(),
            });

            request.respond(Response::from_string(response)).unwrap();
        }
    }
    Ok(())
}

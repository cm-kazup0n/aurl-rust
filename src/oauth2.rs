use rand::distributions::Alphanumeric;
use std::fmt::Display;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use log::{debug, error, info, warn};
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::oauth2::GrantType::{AuthorizationCode, ClientCredentials, Password};
use crate::profile::InvalidConfig;
use crate::version;
use reqwest::header::USER_AGENT;
use std::io::Write;

mod path_util {
    use clap::lazy_static::lazy_static;
    use regex::Regex;

    lazy_static! {
        pub static ref PATH_REGEX: Regex = Regex::new(".*?code=(?P<code>.+)&").unwrap();
    }
}

pub struct OAuth2Config {
    pub auth_server_auth_endpoint: Option<String>,
    pub auth_server_token_endpoint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub grant_type: GrantType,
    pub redirect: Option<String>,
    pub default_content_type: Option<String>,
    pub default_user_agent: Option<String>,
    pub default_auth_header_template: Option<String>,
}

impl OAuth2Config {
    #[allow(dead_code)]
    fn auth_server_auth_endpoint(&self) -> Result<String, AccessTokenError> {
        ok_or(
            self.auth_server_auth_endpoint.clone(),
            "auth_server_auth_endpoint",
        )
    }

    fn auth_server_token_endpoint(&self) -> Result<String, AccessTokenError> {
        ok_or(
            self.auth_server_token_endpoint.clone(),
            "auth_server_token_endpoint",
        )
    }

    fn client_id(&self) -> Result<String, AccessTokenError> {
        ok_or(self.client_id.clone(), "client_id")
    }

    fn username(&self) -> Result<String, AccessTokenError> {
        ok_or(self.username.clone(), "username")
    }

    fn password(&self) -> Result<String, AccessTokenError> {
        ok_or(self.password.clone(), "password")
    }

    fn scopes(&self) -> Result<String, AccessTokenError> {
        ok_or(self.scopes.clone(), "scopes")
    }

    fn redirect(&self) -> Result<String, AccessTokenError> {
        ok_or(self.redirect.clone(), "redirect")
    }
}

fn ok_or<T>(v: Option<T>, fname: &str) -> Result<T, AccessTokenError> {
    v.ok_or_else(|| AccessTokenError::InvalidConfig(fname.to_string()))
}

#[derive(Deserialize, Debug, Serialize)]
pub struct AccessToken {
    pub access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: u64,
    scope: Option<String>,
    id_token: Option<String>,
    ttl: Option<u64>,
}

impl Display for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self).expect("can't parse AccessToken")
        )
    }
}

impl AccessToken {
    // Load AccessToken from Cache
    pub fn load_cache(profile: &str) -> Option<AccessToken> {
        match File::open(AccessToken::cache_file(profile)) {
            Ok(f) => {
                let reader = BufReader::new(f);

                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();

                match serde_json::from_reader::<BufReader<File>, AccessToken>(reader) {
                    // ttl 取得失敗したら 0 とする
                    Ok(t) if t.ttl.unwrap_or(u64::MIN) > now.as_secs() => {
                        debug!("cache is valid. use cache!");
                        Some(t)
                    }
                    _ => None,
                }
            }
            Err(_) => {
                warn!("can not find cache file: {}", &profile);
                None
            }
        }
    }

    // Save AccessToken in Cache
    pub fn save_cache(&mut self, profile: &str) -> Result<(), CacheError> {
        AccessToken::create_cachedir()?;

        // open cache file
        let path = AccessToken::cache_file(profile);
        let mut cache_file = File::create(path).unwrap();

        // Calculate TTL, if ttl is None
        if self.ttl.is_none() {
            self.ttl = Some(AccessToken::calc_ttl(self.expires_in));
        }
        // save json string
        let str = serde_json::to_string(&self).unwrap();
        debug!("Deserialize AccessToken {:?}", str);

        cache_file.write_all(str.as_bytes()).map_err(|_| {
            warn!("can not write cache file.");
            CacheError::InvalidCache("invalid cache".to_string())
        })
    }

    // Remove cache file
    pub fn remove_cache(profile: &str) {
        fs::remove_file(AccessToken::cache_file(profile).as_path()).unwrap_or_else(|_| {
            warn!("can not remove cache");
        })
    }

    // calculate ttl with expires_in in AccessToken
    fn calc_ttl(expires_in: u64) -> u64 {
        // http://openid-foundation-japan.github.io/rfc6749.ja.html#token-response
        // ttl = Epoch Sec + expires_in
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        now.as_secs() + expires_in
    }

    fn basedir() -> PathBuf {
        let mut home = dirs::home_dir().unwrap();
        home.push(".aurl");
        home
    }

    // create Token Cache File path
    fn cache_file(profile: &str) -> PathBuf {
        let mut file = AccessToken::cachedir();
        file.push(profile);
        file.set_extension("json");

        file
    }

    fn cachedir() -> PathBuf {
        let mut dir = AccessToken::basedir();
        dir.push("token");
        dir
    }

    fn create_cachedir() -> Result<(), CacheError> {
        let dirpath = AccessToken::cachedir();
        if !dirpath.exists() && fs::create_dir_all(dirpath).is_err() {
            warn!("can not cache file");
            Err(CacheError::FailedCreateCacheError(
                "can't create cache dir".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub enum CacheError {
    InvalidCache(String),
    FailedCreateCacheError(String),
}

#[cfg(test)]
mod test {

    use std::{thread, time::Duration};

    use super::*;

    #[test]
    fn test_regex_path() {
        match path_util::PATH_REGEX
            .captures("?hogehoge=fugafuga&code=ZZZZ-XXXX-CCCC&state=hogehoge")
        {
            Some(path) => {
                let code = path.name("code").unwrap().as_str();
                assert_eq!(code, "ZZZZ-XXXX-CCCC")
            }
            None => panic!("test failed"),
        }
    }

    #[test]
    fn test_cache_path() {
        // setup
        let home = dirs::home_dir().unwrap();
        let home = home.to_str().unwrap();
        let expected = PathBuf::from(format!("{}/.aurl/token/test.json", home));

        // execute
        let actual = AccessToken::cache_file("test");

        println!("{:?}", actual);

        // verify
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_save_cache() {
        // let data = r#"
        // {
        //     "access_token": "aaaaaa",
        //     "token_type": "bearer",
        //     "expires_in": 3600,
        //     "scope": "root"
        // }"#;

        let mut token = AccessToken {
            access_token: "aaaaaa".to_string(),
            token_type: "bearer".to_string(),
            expires_in: 3600,
            id_token: None,
            refresh_token: None,
            scope: Some("root".to_string()),
            ttl: None,
        };
        let result = token.save_cache("test").unwrap();
        assert_eq!((), result);
    }

    #[test]
    fn test_get_valid_cache() {
        // setup
        let mut token = AccessToken {
            access_token: "aaaaaa".to_string(),
            token_type: "bearer".to_string(),
            expires_in: 3600,
            id_token: None,
            refresh_token: None,
            scope: Some("root".to_string()),
            ttl: None,
        };
        token.save_cache("test_get_valid_cache").unwrap();
        thread::sleep(Duration::from_secs(2));

        // exercise
        let cache = AccessToken::load_cache("test_get_valid_cache");

        // verify
        assert_eq!(true, cache.is_some());

        // clean
        AccessToken::remove_cache("test_get_valid_cache")
    }

    #[test]
    fn test_get_expired_cache() {
        // setup
        let mut token = AccessToken {
            access_token: "aaaaaa".to_string(),
            token_type: "bearer".to_string(),
            expires_in: 1, // 有効時間 1 秒
            id_token: None,
            refresh_token: None,
            scope: Some("root".to_string()),
            ttl: None,
        };
        token.save_cache("test_get_expired_cache").unwrap();
        thread::sleep(Duration::from_secs(5));

        // exercise
        let cache = AccessToken::load_cache("test_get_expired_cache");

        // verify
        assert_eq!(true, cache.is_none());

        // clean
        AccessToken::remove_cache("test_get_expired_cache")
    }

    #[test]
    fn generate_pkce_challenge() {
        // https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
        let (c, m) = GrantType::pkce_challenge(
            PkceMethod::S256,
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        );

        assert_eq!(m, PkceMethod::S256);
        assert_eq!(c, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    #[should_panic]
    fn short_verifier_ng() {
        GrantType::pkce_challenge(PkceMethod::S256, "aaa");
    }

    #[test]
    #[should_panic]
    fn long_verifier_ng() {
        GrantType::pkce_challenge(PkceMethod::S256, "a".repeat(129).as_str());
    }
}

#[derive(Debug)]
pub enum AccessTokenError {
    InvalidConfig(String),
    HttpError(reqwest::Error),
}

impl Display for AccessTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessTokenError::InvalidConfig(s) => write!(f, "Invalid Config: {}", s),
            AccessTokenError::HttpError(e) => write!(f, "{}", e),
        }
    }
}

impl From<reqwest::Error> for AccessTokenError {
    fn from(e: reqwest::Error) -> Self {
        AccessTokenError::HttpError(e)
    }
}

pub enum GrantType {
    Password,
    AuthorizationCode,
    ClientCredentials,
}

impl FromStr for GrantType {
    type Err = InvalidConfig;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "password" => Ok(Password),
            "authorization_code" | "auth" => Ok(AuthorizationCode),
            "client_credentials" | "client" => Ok(ClientCredentials),
            _ => Err(InvalidConfig::InvalidGrantType(s.to_string())),
        }
    }
}

impl GrantType {
    pub async fn get_access_token(
        &self,
        config: &OAuth2Config,
        timeout: u64,
        http: &Client,
    ) -> Result<AccessToken, AccessTokenError> {
        let res = match self {
            GrantType::Password => http
                .post(config.auth_server_token_endpoint()?)
                .basic_auth(config.client_id()?, config.client_secret.clone())
                .header(
                    USER_AGENT,
                    config
                        .default_user_agent
                        .clone()
                        .unwrap_or_else(version::name),
                )
                .form(&[
                    ("grant_type", "password"),
                    ("scope", &config.scopes()?),
                    ("username", &config.username()?),
                    ("password", &config.password()?),
                ]),
            GrantType::ClientCredentials => http
                .post(config.auth_server_token_endpoint()?)
                .basic_auth(config.client_id()?, config.client_secret.clone())
                .header(
                    USER_AGENT,
                    config
                        .default_user_agent
                        .clone()
                        .unwrap_or_else(version::name),
                )
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("scope", &config.scopes()?),
                ]),
            GrantType::AuthorizationCode => {
                // 1. 認可リクエストのURLを作成
                let verifier = PkceMethod::generate_verifier(64);
                let (challenge, method) = GrantType::pkce_challenge(PkceMethod::S256, &verifier);

                let req = http.get(config.auth_server_auth_endpoint()?).query(&[
                    ("response_type", "code"),
                    ("client_id", &config.client_id()?),
                    ("scope", &config.scopes()?),
                    ("state", random().as_str()),
                    ("redirect_uri", config.redirect()?.as_str()),
                    ("code_challenge", &challenge),
                    ("code_challenge_method", method.to_str()),
                ]);

                // 2. 認可リクエストのURLをブラウザで開く
                let req = req.build().unwrap();
                let url = req.url().as_str();
                info!("{}", url);

                webbrowser::open(url).unwrap();

                // 3. URL から認可コードを取得する
                let mut auth_code = String::new();

                // 指定ポートで Callback 待ち構える
                // TODO: port を可変にする
                let server = TcpListener::bind("127.0.0.1:8080").unwrap();
                for stream in server.incoming() {
                    match stream {
                        Ok(stream) => {
                            let mut stream = io::BufReader::new(stream);
                            let mut first_line = String::new();
                            if let Err(error) = stream.read_line(&mut first_line) {
                                error!("{}", error);
                                break;
                            }

                            // スペースで分割
                            let mut params = first_line.split_whitespace();
                            let method = params.next();
                            let path = params.next();
                            let auth_code_result = match (method, path) {
                                (Some("GET"), Some(path)) => {
                                    let stream = stream.get_mut();
                                    println!("path: {}", path);

                                    if let Some(code) = path_util::PATH_REGEX.captures(path) {
                                        let code = code.name("code").unwrap().as_str();

                                        // ブラウザに空レスポンス
                                        writeln!(stream, "HTTP/1.1 200 OK").unwrap();
                                        writeln!(stream, "Content-Type: text/plain; charset=UTF-8")
                                            .unwrap();
                                        writeln!(stream, "{}", code).unwrap();
                                        Ok(code)
                                    } else {
                                        Err("failed capture auth_code")
                                    }
                                }
                                _ => Err("unknown Method"),
                            };
                            match auth_code_result {
                                Ok(code) => auth_code = code.to_string(),
                                Err(str) => error!("{}", str),
                            }
                            break;
                        }
                        Err(_) => {
                            error!("Callback Server error");
                        }
                    }
                }

                // 4. 認可コードをトークンエンドポイントへ POST. AccessToken を取得
                http.post(config.auth_server_token_endpoint()?)
                    .basic_auth(config.client_id()?, config.client_secret.clone())
                    .header(
                        USER_AGENT,
                        config
                            .default_user_agent
                            .clone()
                            .unwrap_or_else(version::name),
                    )
                    .header("content-type", "application/x-www-form-urlencoded")
                    .form(&[
                        ("code", auth_code.trim()),
                        ("grant_type", "authorization_code"),
                        ("redirect_uri", config.redirect()?.as_str()),
                        ("code_verifier", &verifier),
                    ])
            }
        }
        .timeout(Duration::from_secs(timeout))
        .send()
        .await?;
        res.json().await.map_err(AccessTokenError::HttpError)
    }

    fn pkce_challenge(method: PkceMethod, verifier: &str) -> (String, PkceMethod) {
        // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
        assert!(verifier.len() > 42 && verifier.len() <= 128);

        match method {
            PkceMethod::S256 => {
                // verifier を to_ascii -> Sha256 -> Base64urlEncode
                let digest = Sha256::digest(verifier.as_bytes());

                // base64 encode して返す
                (base64_url::encode(&digest), method)
            }
        }
    }
}

// PKCE Method

#[derive(PartialEq, Debug)]
enum PkceMethod {
    S256,
}

impl PkceMethod {
    fn to_str(&self) -> &'static str {
        match self {
            PkceMethod::S256 => "S256",
        }
    }

    fn generate_verifier(len: usize) -> String {
        let s: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(len)
            .map(char::from)
            .collect();
        s
    }
}

// Generate Random State String
fn random() -> String {
    let mut rng = rand::thread_rng();
    let val: i32 = rng.gen();

    // TODO: なんかアレなのでどうにかする
    base64::encode(&val.to_be_bytes())
}

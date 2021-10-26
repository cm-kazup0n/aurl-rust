use std::collections::HashMap;
use std::convert::TryInto;
use std::str::FromStr;

use log::{debug, error, warn};
use reqwest::header::{HeaderMap, CONTENT_TYPE, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::{Client, Response, StatusCode};

use crate::oauth2::{AccessToken, AccessTokenError, OAuth2Config};
use crate::options::Opts;
use crate::version;

#[derive(Debug)]
pub enum RequestError {
    OAuth(AccessTokenError),
    Http(reqwest::Error),
    InvalidHeader(String),
}

pub fn same_origin_redirect_policy() -> Policy {
    //allow redirect to same origin
    Policy::custom(|attempt| {
        if let Some(prev) = attempt.previous().get(0) {
            debug!("Redirect to {:?}", attempt.url().origin());
            debug!("Original request Host = {:?}", prev.origin());
            if attempt.previous().len() > 5 {
                error!("Exceed redirect limit(5)");
                attempt.stop()
            } else if prev.origin() != attempt.url().origin() {
                error!("Redirect to non-same origin resource server");
                attempt.stop()
            } else {
                attempt.follow()
            }
        } else {
            attempt.stop()
        }
    })
}

pub struct Dispatcher {
    pub client: Client,
}

impl Dispatcher {
    pub async fn send(&self, opts: &Opts, oauth2: &OAuth2Config) -> Result<Response, RequestError> {
        let mut hm: HashMap<String, String> = HashMap::with_capacity(opts.header.len());
        for h in opts.header.clone() {
            let kv = h.split(',').collect::<Vec<_>>();
            if kv.len() == 2 {
                if let (Some(k), Some(v)) = (kv.get(0), kv.get(1)) {
                    hm.insert((*k).to_string(), (*v).to_string());
                }
            }
        }
        //set user agent
        if !hm.contains_key(USER_AGENT.as_str()) {
            hm.insert(
                USER_AGENT.to_string(),
                oauth2
                    .default_user_agent
                    .clone()
                    .unwrap_or_else(version::name),
            );
        }

        // set content-type
        if let (false, Some(c)) = (
            hm.contains_key(CONTENT_TYPE.as_str()),
            oauth2.default_content_type.clone(),
        ) {
            hm.insert(CONTENT_TYPE.to_string(), c);
        }

        let headers: HeaderMap = (&hm)
            .try_into()
            .map_err(|e| RequestError::InvalidHeader(format!("{:?}", e)))?;

        loop {
            // test load cache from profile
            let mut token = match AccessToken::load_cache(&opts.profile) {
                Some(t) => t,
                None => oauth2
                    .grant_type
                    .get_access_token(oauth2, &self.client)
                    .await
                    .map_err(RequestError::OAuth)?,
            };
            debug!("Get Token: {:?}", token);

            // save cache with AccessToken
            token
                .save_cache(&opts.profile)
                .unwrap_or_else(|err| warn!("can not save cache. {:?}", err));
            let req = self
                .client
                .request(opts.request.clone(), opts.url.clone())
                .headers(headers.clone());

            let auth_custom_header = oauth2
                .default_auth_header_template
                .clone()
                .unwrap_or_else(|| "".to_string());
            let req = if !auth_custom_header.is_empty() {
                debug!(
                    "custom header option. use custom header: {}",
                    auth_custom_header
                );
                let (header, value) =
                    split_custom_header(&auth_custom_header, &token.access_token).unwrap();
                req.header(
                    reqwest::header::HeaderName::from_str(header).unwrap(),
                    reqwest::header::HeaderValue::from_str(&value).unwrap(),
                )
            } else {
                debug!("non option. use bearer");
                req.bearer_auth(token.access_token)
            };

            debug!("{:?}", req);
            let res = req.send().await;
            debug!("{:?}", res);
            match res {
                Ok(ok) => return Ok(ok),
                Err(e) if e.status().map_or(false, |s| s == StatusCode::UNAUTHORIZED) => {
                    AccessToken::remove_cache(&opts.profile)
                }
                Err(e) => return Err(RequestError::Http(e)),
            }
        }
    }
}

fn split_custom_header<'a>(
    template: &'a str,
    access_token: &'a str,
) -> Result<(&'a str, String), AccessTokenError> {
    let split: Vec<&str> = template.split('=').collect();
    if split.len() != 2 {
        debug!("Failed parse custom_header_template, {}", template);
        Err(AccessTokenError::InvalidConfig(
            "invalid custom_header_template".to_string(),
        ))
    } else if !split[1].to_lowercase().contains("$token") {
        Err(AccessTokenError::InvalidConfig(
            "can't find '$token' placeholder".to_string(),
        ))
    } else {
        let value = split[1]
            .trim()
            .to_lowercase()
            .replace("$token", access_token);
        Ok((split[0], value))
    }
}

use std::collections::HashMap;
use std::fmt::Display;
use std::path::PathBuf;

use tini::Ini;

use crate::oauth2::OAuth2Config;

pub enum InvalidConfig {
    MissingFields(String),
    IniFileError(tini::Error),
    InvalidGrantType(String),
}

impl Display for InvalidConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidConfig::MissingFields(s) => write!(
                f,
                "Missing Configuration Field. Check Your Profile Configuration: {}",
                s
            ),
            InvalidConfig::IniFileError(e) => write!(
                f,
                "Configuration Error. Check Your Profile Configuration: {}",
                e
            ),
            InvalidConfig::InvalidGrantType(s) => write!(f, "Invalid GrantType: {}", s),
        }
    }
}

pub struct Profile {
    pub name: String,
}

impl Profile {
    pub fn new(name: &str) -> Profile {
        Profile {
            name: name.to_string(),
        }
    }

    fn basedir() -> PathBuf {
        let mut home = dirs::home_dir().unwrap();
        home.push(".aurl/");
        home
    }

    pub fn config_file() -> PathBuf {
        let mut file = Profile::basedir();
        file.push("profiles");
        file
    }
}

pub fn read_profiles() -> Result<HashMap<String, OAuth2Config>, InvalidConfig> {
    let config = Ini::from_file(&Profile::config_file()).map_err(InvalidConfig::IniFileError)?;
    let mut profiles: HashMap<String, OAuth2Config> = HashMap::new();

    for (name, section) in config.iter() {
        let profile = OAuth2Config {
            auth_server_auth_endpoint: section.get("auth_server_auth_endpoint"),
            auth_server_token_endpoint: section.get("auth_server_token_endpoint"),
            client_id: section.get("client_id"),
            client_secret: section.get("client_secret"),
            username: section.get("username"),
            password: section.get("password"),
            grant_type: section
                .get("grant_type")
                .ok_or_else(|| InvalidConfig::MissingFields("grant_type".to_string()))?,
            scopes: section.get("scopes"),
            redirect: section.get("redirect"),
            default_content_type: section.get("default_content_type"),
            default_user_agent: section.get("default_user_agent"),
            default_auth_header_template: section.get("default_auth_header_template"),
        };
        profiles.insert(name.to_string(), profile);
    }
    Ok(profiles)
}

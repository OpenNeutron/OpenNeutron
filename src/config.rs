use serde::Deserialize;
use std::fs;
use std::sync::OnceLock;

static GLOBAL_CONFIG: OnceLock<Config> = OnceLock::new();

/// Initialise the global config. Call once at startup before any other code
/// that calls 'config::get()'.
pub fn init(cfg: Config) {
    GLOBAL_CONFIG.set(cfg).expect("config::init called more than once");
}

/// Return a reference to the global config. Panics if 'init' has not been
/// called yet.
pub fn get() -> &'static Config {
    GLOBAL_CONFIG.get().expect("config not initialised - call config::init first")
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerSettings,
    pub storage: StorageSettings,
    pub tls: TlsSettings,
    pub dkim: Option<DkimSettings>,
    pub logging: LoggingSettings,
    pub jwt: Option<JwtSettings>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    pub domain: String,
    pub smtp_port: u16,
    pub api_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageSettings {
    pub users_file: String,
    pub blobs_dir: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsSettings {
    pub self_signed: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingSettings {
    
    pub level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtSettings {
    /// Static secret used to sign/verify JWTs. If absent, a random secret is
    /// generated at startup (tokens become invalid after a restart).
    pub secret: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DkimSettings {
    
    
    pub enabled: bool,
    
    pub private_key_path: Option<String>,
    
    pub selector: Option<String>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerSettings {
                domain: "localhost".to_string(),
                smtp_port: 2525,
                api_port: 8080,
            },
            storage: StorageSettings {
                users_file: "data/users.bin".to_string(),
                blobs_dir: "data/blobs".to_string(),
            },
            tls: TlsSettings {
                self_signed: true,
                cert_path: None,
                key_path: None,
            },
            dkim: None,
            logging: LoggingSettings {
                level: "info".to_string(),
            },
            jwt: None,
        }
    }
}

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub bind: SocketAddr,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub psk_hex: String,
    pub db_path: PathBuf,
    pub files_dir: PathBuf,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
        let cfg: Config = serde_yaml::from_str(&text).with_context(|| format!("parse {path}"))?;
        std::fs::create_dir_all(&cfg.files_dir)?;
        Ok(cfg)
    }

    pub fn psk(&self) -> Result<Vec<u8>> {
        let raw = hex::decode(self.psk_hex.trim()).context("psk_hex is not valid hex")?;
        if raw.len() < 16 {
            anyhow::bail!("psk must be at least 16 bytes");
        }
        Ok(raw)
    }
}

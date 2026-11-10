use serde::{Deserialize, Deserializer, de};
use std::str::FromStr;
use std::{collections::BTreeMap, path::PathBuf};
use thiserror::Error;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read configuration file '{fname}': {source}")]
    Read {
        fname: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse configuration file '{fname}': {source}")]
    Parse {
        fname: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("config: missing the kernel")]
    MissingKernel,
}

#[derive(Debug, Default, FromBytes, FromZeroes, AsBytes, PartialEq, Eq)]
#[repr(transparent)]
pub struct MacAddr([u8; 6]);

impl std::str::FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut mac = [0_u8; 6];
        let bytes: Vec<&str> = s.split(':').collect();
        if bytes.len() != 6 {
            return Err("invalid MAC address format".to_string());
        }
        for (i, b) in bytes.iter().enumerate() {
            mac[i] = u8::from_str_radix(b, 16).map_err(|_| "invalid hex byte".to_string())?;
        }
        Ok(MacAddr(mac))
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
pub struct NetParam {
    pub mac: MacAddr,
    pub mtu: u16,
    pub if_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub kernel: PathBuf,
    pub cmd_line: Option<String>,
    pub initramfs: Option<PathBuf>,
    pub num_cpus: u32,
    pub log_file: PathBuf,

    #[serde(deserialize_with = "parse_log_level")]
    pub log_level: log::LevelFilter,

    #[serde(deserialize_with = "parse_bytes")]
    pub mem_size: usize,
    #[serde(default)]
    pub net: BTreeMap<String, NetParam>,
    #[serde(default)]
    pub blk: Vec<PathBuf>,
}

fn parse_log_level<'de, D>(deserializer: D) -> Result<log::LevelFilter, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let s: String = String::deserialize(deserializer)?;
    log::LevelFilter::from_str(s.as_str())
        .map_err(|e| D::Error::custom(format!("Invalid log level format: '{e:?}'")))
}

fn parse_bytes<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Size {
        Str(String),
        Int(usize),
    }

    match Size::deserialize(deserializer)? {
        Size::Int(value) => Ok(value),
        Size::Str(s) => {
            if let Some(val_str) = s.strip_suffix('M') {
                let value: usize = val_str.parse().map_err(D::Error::custom)?;
                Ok(value << 20)
            } else if let Some(val_str) = s.strip_suffix('G') {
                let value: usize = val_str.parse().map_err(D::Error::custom)?;
                Ok(value << 30)
            } else {
                s.parse().map_err(|_| {
                    D::Error::custom("invalid size format (expected integer or suffix 'M'/'G')")
                })
            }
        }
    }
}

pub fn parse_config(toml_fname: &str) -> Result<Config, Error> {
    let toml_str = std::fs::read_to_string(toml_fname).map_err(|source| Error::Read {
        fname: toml_fname.to_string(),
        source,
    })?;

    toml::from_str::<Config>(toml_str.as_str()).map_err(|source| Error::Parse {
        fname: toml_fname.to_string(),
        source,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_mem_size() {
        let toml_str = r#"
            kernel = "bzImage"
            num_cpus = 4
            mem_size = "256M"
            blk = []
            log_file = "/tmp/log"
            log_level = "info"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.mem_size, 256 << 20);

        let toml_str_int = r#"
            kernel = "bzImage"
            num_cpus = 4
            mem_size = 268435456
            blk = []
            log_file = "/tmp/log"
            log_level = "info"
        "#;
        let config_int: Config = toml::from_str(toml_str_int).unwrap();
        assert_eq!(config_int.mem_size, 268435456);
    }
}

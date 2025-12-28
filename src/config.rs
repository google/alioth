use serde::{Deserialize, Deserializer, de};
use std::num::NonZeroU16;
use std::{collections::BTreeMap, path::PathBuf};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[derive(Debug, Default, FromBytes, FromZeroes, AsBytes, PartialEq, Eq)]
#[repr(transparent)]
pub struct MacAddr([u8; 6]);

fn ox_char_to_byte(b: u8) -> Result<u8, String> {
    if b.is_ascii_digit() {
        return Ok(b - b'0');
    }
    if (b'a'..=b'f').contains(&b) {
        return Ok(b - b'a' + 10);
    }
    if (b'A'..=b'F').contains(&b) {
        return Ok(b - b'A' + 10);
    }

    Err("Failed to parse MAC.".to_owned())
}

impl std::str::FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let maybe_bytes: Vec<&str> = s.split(':').collect();
        if maybe_bytes.len() != 6 {
            return Err(format!("Failed to parse MAC: {s}."));
        }

        let mut mac = [0_u8; 6];
        for idx in 0..6 {
            let maybe_byte = maybe_bytes[idx].as_bytes();
            if maybe_byte.len() != 2 {
                return Err(format!("Failed to parse MAC: {s}."));
            }

            let b0 = ox_char_to_byte(maybe_byte[0])?;
            let b1 = ox_char_to_byte(maybe_byte[1])?;
            mac[idx] = (b0 << 4) + b1;
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
    pub queue_pairs: Option<NonZeroU16>,
    pub if_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub kernel: Option<PathBuf>,
    pub pvh: Option<PathBuf>,
    pub cmd_line: Option<String>,
    pub initramfs: Option<PathBuf>,
    pub num_cpus: u32,

    #[serde(deserialize_with = "parse_bytes")]
    pub mem_size: usize,
    pub net: BTreeMap<String, NetParam>,
    pub blk: Vec<PathBuf>,
}

fn parse_bytes<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let s: String = String::deserialize(deserializer)?;
    if s.ends_with("M") {
        let value: usize = s[..s.len() - 1].parse().map_err(D::Error::custom)?;
        Ok(value << 20)
    } else if s.ends_with("G") {
        let value: usize = s[..s.len() - 1].parse().map_err(D::Error::custom)?;
        Ok(value << 30)
    } else {
        Err(D::Error::custom("invalid size format"))
    }
}

pub fn parse_config(toml_fname: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let toml_str = std::fs::read_to_string(toml_fname)?;

    toml::from_str::<Config>(toml_str.as_str()).map_err(|e| e.into())
}

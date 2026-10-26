use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::str::FromStr;
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

impl FromStr for MacAddr {
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

#[derive(Debug)]
pub struct NetParam {
    pub mac: MacAddr,
    pub mtu: u16,
    pub queue_pairs: Option<NonZeroU16>,
    pub if_name: Option<String>,
}

#[derive(Debug)]
pub struct Config {
    pub kernel: Option<PathBuf>,
    pub pvh: Option<PathBuf>,
    pub cmd_line: Option<String>,
    pub initramfs: Option<PathBuf>,
    pub num_cpus: u32,
    pub log_file: PathBuf,
    pub log_level: log::LevelFilter,
    pub mem_size: usize,
    pub net: BTreeMap<String, NetParam>,
    pub blk: Vec<PathBuf>,
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_quotes => {
                i += 2;
                continue;
            }
            b'"' => in_quotes = !in_quotes,
            b'#' if !in_quotes => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

fn parse_string(val: &str) -> Result<String, String> {
    let val = val.trim();
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        Ok(val[1..val.len() - 1].to_owned())
    } else if val.len() >= 2 && val.starts_with('\'') && val.ends_with('\'') {
        Ok(val[1..val.len() - 1].to_owned())
    } else {
        Err(format!("expected quoted string, got '{val}'"))
    }
}

fn parse_string_array(val: &str) -> Result<Vec<PathBuf>, String> {
    let val = val.trim();
    if !val.starts_with('[') || !val.ends_with(']') {
        return Err(format!("expected array [...], got '{val}'"));
    }
    let inner = val[1..val.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        out.push(PathBuf::from(parse_string(item)?));
    }
    Ok(out)
}

fn parse_bytes(s: &str) -> Result<usize, String> {
    let s = parse_string(s)?;
    if let Some(num) = s.strip_suffix('M') {
        let value: usize = num.parse().map_err(|e| format!("invalid mem_size '{s}': {e}"))?;
        Ok(value << 20)
    } else if let Some(num) = s.strip_suffix('G') {
        let value: usize = num.parse().map_err(|e| format!("invalid mem_size '{s}': {e}"))?;
        Ok(value << 30)
    } else {
        Err(format!("invalid size format '{s}'"))
    }
}

#[derive(Default)]
struct PartialNetParam {
    mac: Option<MacAddr>,
    mtu: Option<u16>,
    queue_pairs: Option<NonZeroU16>,
    if_name: Option<String>,
}

pub fn parse_config(toml_fname: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let toml_str = std::fs::read_to_string(toml_fname)?;

    let mut kernel: Option<PathBuf> = None;
    let mut pvh: Option<PathBuf> = None;
    let mut cmd_line: Option<String> = None;
    let mut initramfs: Option<PathBuf> = None;
    let mut num_cpus: Option<u32> = None;
    let mut log_file: Option<PathBuf> = None;
    let mut log_level: Option<log::LevelFilter> = None;
    let mut mem_size: Option<usize> = None;
    let mut blk: Option<Vec<PathBuf>> = None;
    let mut net_partials: BTreeMap<String, PartialNetParam> = BTreeMap::new();

    let mut current_section = String::new();

    for (line_idx, raw_line) in toml_str.lines().enumerate() {
        let line_no = line_idx + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].trim().to_owned();
            continue;
        }

        let Some((raw_key, raw_val)) = line.split_once('=') else {
            return Err(format!("line {line_no}: expected key = value, got '{line}'").into());
        };
        let key = raw_key.trim();
        let val = raw_val.trim();

        if current_section.is_empty() {
            match key {
                "kernel" => kernel = Some(PathBuf::from(parse_string(val)?)),
                "pvh" => pvh = Some(PathBuf::from(parse_string(val)?)),
                "cmd_line" => cmd_line = Some(parse_string(val)?),
                "initramfs" => initramfs = Some(PathBuf::from(parse_string(val)?)),
                "num_cpus" => {
                    num_cpus = Some(
                        val.parse()
                            .map_err(|e| format!("line {line_no}: invalid num_cpus: {e}"))?,
                    )
                }
                "log_file" => log_file = Some(PathBuf::from(parse_string(val)?)),
                "log_level" => {
                    let s = parse_string(val)?;
                    let lvl = log::LevelFilter::from_str(&s)
                        .map_err(|e| format!("line {line_no}: invalid log_level '{s}': {e:?}"))?;
                    log_level = Some(lvl);
                }
                "mem_size" => mem_size = Some(parse_bytes(val)?),
                "blk" => blk = Some(parse_string_array(val)?),
                other => {
                    return Err(format!("line {line_no}: unknown config key '{other}'").into());
                }
            }
        } else if let Some(dev_name) = current_section.strip_prefix("net.") {
            let entry = net_partials.entry(dev_name.trim().to_owned()).or_default();
            match key {
                "mac" => {
                    let s = parse_string(val)?;
                    entry.mac = Some(MacAddr::from_str(&s)?);
                }
                "mtu" => {
                    entry.mtu = Some(
                        val.parse()
                            .map_err(|e| format!("line {line_no}: invalid mtu: {e}"))?,
                    );
                }
                "queue_pairs" => {
                    let n: u16 = val
                        .parse()
                        .map_err(|e| format!("line {line_no}: invalid queue_pairs: {e}"))?;
                    entry.queue_pairs = Some(
                        NonZeroU16::new(n)
                            .ok_or_else(|| format!("line {line_no}: queue_pairs must be > 0"))?,
                    );
                }
                "if_name" => entry.if_name = Some(parse_string(val)?),
                other => {
                    return Err(
                        format!("line {line_no}: unknown [net.{dev_name}] key '{other}'").into(),
                    );
                }
            }
        } else if current_section == "net" {
            return Err(
                format!("line {line_no}: unexpected key '{key}' under [net]; use [net.<dev>]")
                    .into(),
            );
        } else {
            return Err(
                format!("line {line_no}: unknown section '[{current_section}]'").into(),
            );
        }
    }

    let mut net = BTreeMap::new();
    for (name, p) in net_partials {
        net.insert(
            name.clone(),
            NetParam {
                mac: p.mac.ok_or_else(|| format!("missing mac in [net.{name}]"))?,
                mtu: p.mtu.ok_or_else(|| format!("missing mtu in [net.{name}]"))?,
                queue_pairs: p.queue_pairs,
                if_name: p.if_name,
            },
        );
    }

    Ok(Config {
        kernel,
        pvh,
        cmd_line,
        initramfs,
        num_cpus: num_cpus.ok_or("missing num_cpus in config")?,
        log_file: log_file.ok_or("missing log_file in config")?,
        log_level: log_level.ok_or("missing log_level in config")?,
        mem_size: mem_size.ok_or("missing mem_size in config")?,
        net,
        blk: blk.unwrap_or_default(),
    })
}

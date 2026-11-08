use std::time::Duration;

/// Loopback HTTP target for the bridge. The address is pre-validated:
/// http scheme, no credentials, no path/query/fragment, loopback host only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetUrl {
    pub host: String,
    pub port: u16,
}

impl TargetUrl {
    /// Canonical http URL for this target, used for display and proxy Host.
    pub fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

#[derive(Debug)]
pub struct Config {
    pub command: Vec<String>,
    pub port: u16,
    pub tailscale_cli: Option<String>,
    pub target: Option<TargetUrl>,
    pub timeout: Duration,
}

#[derive(Debug)]
pub enum ParseOutcome {
    Config(Config),
    /// No command and no target: show the dashboard.
    Dashboard {
        tailscale_cli: Option<String>,
    },
    Version(String),
    Help,
}

/// A command line Porthmeus cannot run; exits 2 with a short usage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliError {
    BadSyntax(String),
    UnknownFlag(String),
    MissingValue(String),
    InvalidValue {
        flag: &'static str,
        value: String,
        reason: String,
    },
    /// A flag that only applies when serving, given without a command.
    NeedsCommand(&'static str),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSyntax(item) => write!(formatter, "bad flag syntax: {item}"),
            Self::UnknownFlag(name) => write!(formatter, "unknown flag: {}", dashed(name)),
            Self::MissingValue(name) => {
                write!(formatter, "flag needs an argument: {}", dashed(name))
            }
            Self::InvalidValue {
                flag,
                value,
                reason,
            } => write!(formatter, "invalid --{flag} {value:?}: {reason}"),
            Self::NeedsCommand(flag) => {
                write!(formatter, "--{flag} needs a command or --target")
            }
        }
    }
}

/// `-h` stays short; every other flag reads as `--name`.
fn dashed(name: &str) -> String {
    if name.chars().count() == 1 {
        format!("-{name}")
    } else {
        format!("--{name}")
    }
}

enum Step {
    End,
    Terminator,
    Flag(String, String),
}

/// Flags that default to true and may appear without a value.
const BOOLEAN_FLAGS: [&str; 3] = ["version", "help", "h"];
/// Flags that take the next argument as their value.
const VALUE_FLAGS: [&str; 4] = ["https", "target", "timeout", "tailscale-cli"];

struct FlagParser<'a> {
    args: &'a [String],
    index: usize,
}

impl<'a> FlagParser<'a> {
    fn new(args: &'a [String]) -> Self {
        Self { args, index: 0 }
    }

    /// Returns End at end of input, Terminator for "--", or the next flag.
    fn next(&mut self) -> Result<Step, CliError> {
        let Some(item) = self.args.get(self.index) else {
            return Ok(Step::End);
        };
        if item == "--" {
            self.index += 1;
            return Ok(Step::Terminator);
        }
        if !item.starts_with('-') || item == "-" {
            return Ok(Step::End);
        }
        let name = item.trim_start_matches('-');
        if name.is_empty() {
            return Err(CliError::BadSyntax(item.clone()));
        }
        if let Some((key, value)) = name.split_once('=') {
            if key.is_empty() {
                return Err(CliError::BadSyntax(item.clone()));
            }
            self.index += 1;
            return Ok(Step::Flag(key.to_string(), value.to_string()));
        }
        self.index += 1;
        if BOOLEAN_FLAGS.contains(&name) {
            // Boolean flags default to true; an explicit =value form is handled above.
            return Ok(Step::Flag(name.to_string(), "true".to_string()));
        }
        if !VALUE_FLAGS.contains(&name) {
            return Err(CliError::UnknownFlag(name.to_string()));
        }
        let Some(value) = self.args.get(self.index) else {
            return Err(CliError::MissingValue(name.to_string()));
        };
        self.index += 1;
        Ok(Step::Flag(name.to_string(), value.clone()))
    }

    fn remaining(&self) -> Vec<String> {
        self.args.get(self.index..).unwrap_or_default().to_vec()
    }
}

fn parse_duration(text: &str) -> Result<Duration, String> {
    let units: &[(&str, u64)] = &[
        ("ns", 0),
        ("us", 0),
        ("µs", 0),
        ("ms", 0),
        ("s", 1_000_000_000),
        ("m", 60_000_000_000),
        ("h", 3_600_000_000_000),
    ];
    let unit_start = text
        .find(|character: char| !(character.is_ascii_digit() || character == '.'))
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(unit_start);
    if number.is_empty() || unit.is_empty() {
        return Err("expected a number and a unit, like 30s or 5m".to_string());
    }
    let value: f64 = number
        .parse()
        .map_err(|_| "expected a number and a unit, like 30s or 5m".to_string())?;
    let multiplier = units
        .iter()
        .find(|(name, _)| *name == unit)
        .map(|(_, multiplier)| *multiplier)
        .ok_or_else(|| format!("unknown unit {unit:?}; use s, m, or h"))?;
    if multiplier == 0 {
        return Err("sub-second durations are not supported".to_string());
    }
    let nanos = value * (multiplier as f64);
    if !(nanos.is_finite()) || nanos < 0.0 || nanos > (u64::MAX as f64) {
        return Err("out of range".to_string());
    }
    Ok(Duration::from_nanos(nanos as u64))
}

fn parse_target(value: &str) -> Result<TargetUrl, String> {
    let rejected = || {
        "must be a loopback http:// URL without credentials, path, query, or fragment".to_string()
    };
    let rest = value.strip_prefix("http://").ok_or_else(rejected)?;
    let authority = match rest.find(['/', '?', '#']) {
        Some(index) => &rest[..index],
        None => rest,
    };
    let path = &rest[authority.len()..];
    if path.starts_with('/') && path != "/" {
        return Err(rejected());
    }
    if path.starts_with('?') || path.starts_with('#') {
        return Err(rejected());
    }
    if authority.is_empty() || authority.contains('@') {
        return Err(rejected());
    }
    let (host_text, port) = if let Some(inner) = authority.strip_prefix('[') {
        let close = inner
            .find(']')
            .ok_or_else(|| "invalid IPv6 address".to_string())?;
        let host = &inner[..close];
        let after = &inner[close + 1..];
        let port_text = after.strip_prefix(':').ok_or_else(rejected)?;
        (host, Some(port_text))
    } else if let Some(colon) = authority.rfind(':') {
        (&authority[..colon], Some(&authority[colon + 1..]))
    } else {
        (authority, None)
    };
    let port = match port {
        None => 80,
        Some("0") => return Err("port cannot be zero".to_string()),
        Some(text) => text
            .parse::<u16>()
            .map_err(|_| "invalid port".to_string())?,
    };
    let host = host_text
        .strip_suffix('.')
        .unwrap_or(host_text)
        .to_ascii_lowercase();
    if !is_loopback_host(&host) {
        return Err(rejected());
    }
    Ok(TargetUrl { host, port })
}

fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Parses `porthmeus [flags] [COMMAND...]`. Without a command or `--target`
/// the outcome is the dashboard; a program whose name starts with `-` goes
/// after `--`.
pub fn parse_config(args: &[String]) -> Result<ParseOutcome, CliError> {
    let mut https_port: Option<u16> = None;
    let mut tailscale_cli: Option<String> = None;
    let mut target: Option<TargetUrl> = None;
    let mut version = false;
    let mut timeout: Option<Duration> = None;
    let mut help = false;
    let mut parser = FlagParser::new(args);
    loop {
        match parser.next()? {
            Step::End | Step::Terminator => break,
            Step::Flag(name, value) => match name.as_str() {
                "https" => https_port = Some(parse_port(&value)?),
                "tailscale-cli" => tailscale_cli = Some(value),
                "target" => {
                    target =
                        Some(
                            parse_target(&value).map_err(|reason| CliError::InvalidValue {
                                flag: "target",
                                value: value.clone(),
                                reason,
                            })?,
                        )
                }
                "timeout" => {
                    let parsed = parse_duration(&value)
                        .and_then(|duration| {
                            if duration.is_zero() {
                                Err("must be positive".to_string())
                            } else {
                                Ok(duration)
                            }
                        })
                        .map_err(|reason| CliError::InvalidValue {
                            flag: "timeout",
                            value: value.clone(),
                            reason,
                        })?;
                    timeout = Some(parsed);
                }
                "version" => version = parse_flag_value(&value, "version")?,
                "help" | "h" => help = true,
                _ => return Err(CliError::UnknownFlag(name)),
            },
        }
    }
    if help {
        return Ok(ParseOutcome::Help);
    }
    if version {
        return Ok(ParseOutcome::Version(env!("CARGO_PKG_VERSION").to_string()));
    }
    let command = parser.remaining();
    if command.is_empty() && target.is_none() {
        if https_port.is_some() {
            return Err(CliError::NeedsCommand("https"));
        }
        if timeout.is_some() {
            return Err(CliError::NeedsCommand("timeout"));
        }
        return Ok(ParseOutcome::Dashboard { tailscale_cli });
    }
    Ok(ParseOutcome::Config(Config {
        command,
        port: https_port.unwrap_or(0),
        tailscale_cli,
        target,
        timeout: timeout.unwrap_or(Duration::from_secs(30)),
    }))
}

fn parse_port(value: &str) -> Result<u16, CliError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| CliError::InvalidValue {
            flag: "https",
            value: value.to_string(),
            reason: "must be between 1 and 65535".to_string(),
        })
}

fn parse_flag_value(value: &str, flag: &'static str) -> Result<bool, CliError> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(CliError::InvalidValue {
            flag,
            value: value.to_string(),
            reason: "expected true or false".to_string(),
        }),
    }
}

/// The synopsis shown under a usage error.
pub const SHORT_USAGE: &str = "Usage:
  porthmeus [flags] COMMAND [ARGS...]
  porthmeus
";

pub const USAGE: &str = "Open your dev server on any device in your tailnet.

Usage:
  porthmeus [flags] COMMAND [ARGS...]  run COMMAND and serve it at a private HTTPS link
  porthmeus [flags] --target URL       serve a server that is already running
  porthmeus                            show every listening port (the dashboard)

Examples:
  porthmeus vp dev
  p python3 -m http.server
  porthmeus --target http://127.0.0.1:8080

Flags:
      --https PORT          tailnet HTTPS port (default: an unused port)
      --target URL          serve this loopback URL instead of discovering one
      --timeout DURATION    wait DURATION for the server to listen (default 30s)
      --tailscale-cli PATH  use this tailscale CLI instead of tailscaled's socket
  -h, --help                show this help
      --version             print the version

Dashboard keys:
  up/down, j/k  select a port
  x             stop it (yours only; x again force-kills)
  m             show only your ports, or all
  r             refresh
  q             quit

`p` is short for `porthmeus`. Put `--` before a command that starts with `-`.
";

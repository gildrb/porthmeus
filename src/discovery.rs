use crate::cli::TargetUrl;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const PROBE_TIMEOUT: Duration = Duration::from_millis(400);

/// A listening TCP socket. The kernel reports every socket's owner uid and
/// cgroup; the holding process is known only when its descriptors are
/// readable (the caller's own processes, or all of them as root).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub pid: Option<u32>,
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub uid: Option<u32>,
    /// cgroup v2 id of the socket's creator (Linux): the inode of its
    /// directory below /sys/fs/cgroup.
    pub cgroup: Option<u64>,
}

/// Process metadata used by the dashboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub name: String,
    pub command: String,
}

/// A process owned by the spawned child, with its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedProcess {
    pub pid: u32,
    pub ppid: u32,
}

/// A loopback address the owned processes listen on, and the process holding it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopbackListener {
    pub address: String,
    pub pid: u32,
}

/// Outcome of one discovery poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Discovery {
    Found(TargetUrl),
    /// Nothing selectable yet. Lists the listeners that answered without a
    /// 2xx or 3xx status; empty when nothing answered.
    Pending(Vec<Probe>),
}

/// A loopback listener that answered `GET /` with bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub address: String,
    /// HTTP status from the response line, if one could be parsed.
    pub status: Option<u16>,
}

impl Probe {
    fn ready(&self) -> bool {
        self.status
            .is_some_and(|status| (200..400).contains(&status))
    }
}

/// Formats probes as `address (status)` for error messages.
pub fn describe(probes: &[Probe]) -> String {
    probes
        .iter()
        .map(|probe| match probe.status {
            Some(status) => format!("{} ({status})", probe.address),
            None => format!("{} (no status)", probe.address),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Polls the child's owned process set for its loopback HTTP listener. Only
/// the listeners of the shallowest processes in the child's tree are probed:
/// a dev server's helpers run below it (workerd under Vite), and some of their
/// sockets are not HTTP, so a probe would corrupt their protocol or reach a
/// port that is not the site. The one listener answering 2xx or 3xx is
/// chosen. A listener answering anything else is not chosen here, even alone:
/// a helper on the same process (Node's inspector) can listen before the dev
/// server does. The runner takes a sole such listener at the deadline
/// (`target`). Returns Pending while nothing is selectable.
pub fn discover_target(root_pid: u32) -> Result<Discovery, String> {
    let owned = owned_processes(root_pid);
    if owned.is_empty() {
        return Ok(Discovery::Pending(Vec::new()));
    }
    let pids: Vec<u32> = owned.iter().map(|process| process.pid).collect();
    let listeners = loopback_listeners(&pids)?;
    let probes = probe_listeners(shallowest(&owned, listeners));
    let ready: Vec<&Probe> = probes.iter().filter(|probe| probe.ready()).collect();
    match ready.as_slice() {
        [] => Ok(Discovery::Pending(probes)),
        [chosen] => target(chosen).map(Discovery::Found),
        _ => {
            let addresses: Vec<&str> = ready.iter().map(|probe| probe.address.as_str()).collect();
            Err(format!(
                "multiple child HTTP listeners found: {addresses:?}; select one with --target"
            ))
        }
    }
}

/// The URL of a probed listener.
pub fn target(probe: &Probe) -> Result<TargetUrl, String> {
    let (host, port) = split_host_port(&probe.address)?;
    let port =
        u16::try_from(port).map_err(|_| format!("invalid listener port {:?}", probe.address))?;
    Ok(TargetUrl { host, port })
}

/// Addresses of the listeners whose processes have the fewest owned
/// ancestors. Depth counts owned ancestors, so it is defined for process
/// group members that are not descendants of the root.
fn shallowest(owned: &[OwnedProcess], listeners: Vec<LoopbackListener>) -> Vec<String> {
    let parents: HashMap<u32, u32> = owned
        .iter()
        .map(|process| (process.pid, process.ppid))
        .collect();
    let depth = |pid: u32| {
        let mut depth = 0usize;
        let mut current = pid;
        // Bounded by the owned set, so a pid reuse cycle cannot loop forever.
        while let Some(&parent) = parents.get(&current) {
            if parent == current || !parents.contains_key(&parent) || depth >= parents.len() {
                break;
            }
            depth += 1;
            current = parent;
        }
        depth
    };
    let depths: Vec<(usize, String)> = listeners
        .into_iter()
        .map(|listener| (depth(listener.pid), listener.address))
        .collect();
    let Some(minimum) = depths.iter().map(|(depth, _)| *depth).min() else {
        return Vec::new();
    };
    depths
        .into_iter()
        .filter(|(depth, _)| *depth == minimum)
        .map(|(_, address)| address)
        .collect()
}

pub fn required_tools_missing() -> Option<&'static str> {
    tool_missing("ps")
}

#[cfg(not(target_os = "linux"))]
fn tool_missing(name: &str) -> Option<&'static str> {
    for directory in std::env::split_paths(&std::env::var("PATH").unwrap_or_default()) {
        let candidate = directory.join(name);
        if let Ok(metadata) = std::fs::metadata(&candidate) {
            if metadata.is_file() {
                return None;
            }
        }
    }
    Some("lsof")
}

#[cfg(target_os = "linux")]
fn tool_missing(_name: &str) -> Option<&'static str> {
    None
}

fn probe_listeners(addresses: Vec<String>) -> Vec<Probe> {
    let mut responding: Vec<Probe> = addresses
        .into_iter()
        .filter_map(|address| probe(&address).map(|status| Probe { address, status }))
        .collect();
    responding.sort_by(|a, b| a.address.cmp(&b.address));
    responding
}

/// Sends `GET /` and reads the status line. None when the listener sent no
/// bytes; Some(None) when it sent bytes without a parsable HTTP status.
fn probe(address: &str) -> Option<Option<u16>> {
    let mut stream = TcpStream::connect_timeout(&parse_address(address), PROBE_TIMEOUT).ok()?;
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PROBE_TIMEOUT));
    let request = format!("GET / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut head = [0u8; 64];
    let mut len = 0;
    while len < head.len() && !head[..len].contains(&b'\n') {
        match stream.read(&mut head[len..]) {
            Ok(0) | Err(_) => break,
            Ok(read) => len += read,
        }
    }
    if len == 0 {
        return None;
    }
    Some(parse_status(&head[..len]))
}

/// Parses the status code from an `HTTP/x.y NNN ...` response line.
fn parse_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|&byte| byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split_ascii_whitespace();
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse().ok()
}

fn parse_address(address: &str) -> std::net::SocketAddr {
    use std::net::ToSocketAddrs;
    address
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .unwrap_or_else(|| "127.0.0.1:0".parse().expect("valid fallback address"))
}

fn split_host_port(address: &str) -> Result<(String, u32), String> {
    if let Some(inner) = address.strip_prefix('[') {
        let Some(close) = inner.find(']') else {
            return Err(format!("invalid listener address {address:?}"));
        };
        let host = inner[..close].to_string();
        let port = inner[close + 1..]
            .strip_prefix(':')
            .ok_or_else(|| format!("invalid listener address {address:?}"))?;
        let port: u32 = port
            .parse()
            .map_err(|_| format!("invalid listener port {address:?}"))?;
        return Ok((host, port));
    }
    let Some(colon) = address.rfind(':') else {
        return Err(format!("invalid listener address {address:?}"));
    };
    let host = address[..colon].to_string();
    let port: u32 = address[colon + 1..]
        .parse()
        .map_err(|_| format!("invalid listener port {address:?}"))?;
    Ok((host, port))
}

/// Account names by uid from /etc/passwd. Directory-service accounts (macOS,
/// LDAP) are absent; callers show those by number.
pub fn user_names() -> HashMap<u32, String> {
    let Ok(text) = std::fs::read_to_string("/etc/passwd") else {
        return HashMap::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next().filter(|name| !name.is_empty())?;
            let _password = fields.next()?;
            let uid = fields.next()?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

/// systemd's DynamicUser= range (`systemd-analyze` docs): accounts that
/// exist only while their service runs and are absent from /etc/passwd.
pub const DYNAMIC_USERS: std::ops::RangeInclusive<u32> = 61_184..=65_519;
const USERDB_SOCKET: &str = "/run/systemd/userdb/io.systemd.DynamicUser";
const USERDB_TIMEOUT: Duration = Duration::from_millis(200);
const USERDB_MAX_BYTES: usize = 64 * 1024;

/// The name of a DynamicUser= account, from systemd's userdb varlink
/// socket (NUL-terminated JSON messages); None where there is no such socket.
pub fn dynamic_user_name(uid: u32) -> Option<String> {
    let mut stream = std::os::unix::net::UnixStream::connect(USERDB_SOCKET).ok()?;
    stream.set_read_timeout(Some(USERDB_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(USERDB_TIMEOUT)).ok()?;
    let request = serde_json::json!({
        "method": "io.systemd.UserDatabase.GetUserRecord",
        "parameters": { "uid": uid, "service": "io.systemd.DynamicUser" },
    });
    let mut bytes = serde_json::to_vec(&request).ok()?;
    bytes.push(0);
    stream.write_all(&bytes).ok()?;
    let mut reply = Vec::new();
    let mut chunk = [0u8; 4096];
    while !reply.contains(&0) {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 || reply.len() + read > USERDB_MAX_BYTES {
            return None;
        }
        reply.extend_from_slice(&chunk[..read]);
    }
    let end = reply.iter().position(|byte| *byte == 0)?;
    let value: serde_json::Value = serde_json::from_slice(&reply[..end]).ok()?;
    value
        .pointer("/parameters/record/userName")?
        .as_str()
        .map(str::to_string)
}

#[cfg(target_os = "linux")]
pub use proc_scan::{
    all_listeners, cgroup_index, cgroup_members, current_uid, listen_signature, loopback_listeners,
    owned_processes, process_table, process_uid, working_directories,
};

#[cfg(target_os = "linux")]
mod proc_scan;

#[cfg(not(target_os = "linux"))]
pub use fallback_scan::{
    all_listeners, cgroup_index, cgroup_members, current_uid, listen_signature, loopback_listeners,
    owned_processes, process_table, process_uid, working_directories,
};

#[cfg(not(target_os = "linux"))]
mod fallback_scan;

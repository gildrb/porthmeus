use super::{Listener, LoopbackListener, OwnedProcess, ProcessInfo};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

/// Extracts (pid, ppid, pgid) from /proc/<pid>/stat. comm may contain spaces
/// and parentheses, so parsing starts after the last closing ')'.
fn stat_fields(text: &str) -> Option<(i64, i64, i64)> {
    let close = text.rfind(')')?;
    let pid: i64 = text[..close].split_whitespace().next()?.parse().ok()?;
    let mut fields = text[close + 1..].split_whitespace();
    let _state = fields.next()?;
    let ppid = fields.next()?.parse().ok()?;
    let pgid = fields.next()?.parse().ok()?;
    Some((pid, ppid, pgid))
}

/// Every process owned by the spawned child: its process group plus all
/// ppid-descendants, which covers servers that detach into new sessions.
pub fn owned_processes(root_pid: u32) -> Vec<OwnedProcess> {
    let root = root_pid as i64;
    let mut table: HashMap<i64, (i64, i64)> = HashMap::new();
    for pid in proc_pids() {
        if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some((pid, ppid, pgid)) = stat_fields(&text) {
                table.insert(pid, (ppid, pgid));
            }
        }
    }
    let root_pgid = table.get(&root).map(|(_, pgid)| *pgid).unwrap_or(root);
    let mut owned: BTreeSet<i64> = BTreeSet::new();
    for (pid, (_, pgid)) in &table {
        if *pgid == root_pgid {
            owned.insert(*pid);
        }
    }
    let mut frontier: Vec<i64> = owned.iter().copied().collect();
    while let Some(pid) = frontier.pop() {
        for (candidate, (ppid, _)) in &table {
            if *ppid == pid && owned.insert(*candidate) {
                frontier.push(*candidate);
            }
        }
    }
    owned
        .into_iter()
        .filter_map(|pid| {
            let (ppid, _) = table.get(&pid)?;
            Some(OwnedProcess {
                pid: u32::try_from(pid).ok()?,
                ppid: u32::try_from(*ppid).ok()?,
            })
        })
        .collect()
}

fn proc_pids() -> impl Iterator<Item = u32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
}

/// Every visible process with its parent, group, name, and command line.
pub fn process_table() -> Vec<ProcessInfo> {
    let mut processes = Vec::new();
    for pid in proc_pids() {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((_, ppid, pgid)) = stat_fields(&stat) else {
            continue;
        };
        let (Ok(ppid), Ok(pgid)) = (u32::try_from(ppid), u32::try_from(pgid)) else {
            continue;
        };
        let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|text| text.trim_end().to_string())
            .unwrap_or_default();
        let command = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|part| !part.is_empty())
                    .map(String::from_utf8_lossy)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        processes.push(ProcessInfo {
            pid,
            ppid,
            pgid,
            name,
            command,
        });
    }
    processes
}

/// Maps socket inodes to the pid holding them. /proc/<pid>/fd is readable
/// only for the caller's own processes (or all of them as root).
fn socket_owners(pids: impl Iterator<Item = u32>) -> HashMap<u64, u32> {
    let mut owners = HashMap::new();
    for pid in pids {
        let directory = PathBuf::from(format!("/proc/{pid}/fd"));
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(target) = std::fs::read_link(entry.path()) else {
                continue;
            };
            let Some(inode) = target
                .to_str()
                .and_then(|text| text.strip_prefix("socket:["))
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|inode| inode.parse::<u64>().ok())
            else {
                continue;
            };
            owners.entry(inode).or_insert(pid);
        }
    }
    owners
}

/// Every TCP socket in LISTEN state held by one of `owners`, with its pid.
fn listening_sockets(owners: &HashMap<u64, u32>) -> Result<Vec<(u32, ListenSocket)>, String> {
    if owners.is_empty() {
        return Ok(Vec::new());
    }
    Ok(listen_table()?
        .into_iter()
        .filter_map(|socket| owners.get(&socket.inode).map(|pid| (*pid, socket)))
        .collect())
}

/// Current directory of each pid, where readable.
pub fn working_directories(pids: &[u32]) -> HashMap<u32, String> {
    pids.iter()
        .filter_map(|pid| {
            let path = std::fs::read_link(format!("/proc/{pid}/cwd")).ok()?;
            Some((*pid, path.to_string_lossy().into_owned()))
        })
        .collect()
}

/// Cheap fingerprint of every LISTEN socket (address, port, inode): one
/// kernel query, no per-process work. Equal fingerprints mean the full scan
/// would find the same listeners.
pub fn listen_signature() -> Result<String, String> {
    use std::fmt::Write as _;
    let mut signature = String::new();
    for socket in listen_table()? {
        // Writing to a String cannot fail.
        let _ = writeln!(signature, "{} {} {}", socket.ip, socket.port, socket.inode);
    }
    Ok(signature)
}

/// Every listening TCP socket on the machine. The pid is set where this user
/// can read the holder's descriptors; uid and cgroup come from the kernel.
pub fn all_listeners() -> Result<Vec<Listener>, String> {
    let sockets = listen_table()?;
    let owners = socket_owners(proc_pids());
    Ok(sockets
        .into_iter()
        .map(|socket| Listener {
            pid: owners.get(&socket.inode).copied(),
            ip: socket.ip,
            port: socket.port,
            uid: Some(socket.uid),
            cgroup: socket.cgroup,
        })
        .collect())
}

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Path below /sys/fs/cgroup of every cgroup v2 directory, keyed by cgroup
/// id, which on 64-bit kernels is the directory's inode. Reads directory
/// entries only; no stat per cgroup.
pub fn cgroup_index() -> HashMap<u64, String> {
    use std::os::unix::fs::{DirEntryExt as _, MetadataExt as _};
    let mut index = HashMap::new();
    let Ok(root) = std::fs::metadata(CGROUP_ROOT) else {
        return index;
    };
    index.insert(root.ino(), "/".to_string());
    let mut pending = vec![String::new()];
    while let Some(relative) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(format!("{CGROUP_ROOT}{relative}")) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let path = format!("{relative}/{name}");
            index.insert(entry.ino(), path.clone());
            pending.push(path);
        }
    }
    index
}

/// Pids in the cgroup at `path` (as returned by `cgroup_index`); readable by
/// everyone.
pub fn cgroup_members(path: &str) -> Vec<u32> {
    std::fs::read_to_string(format!("{CGROUP_ROOT}{path}/cgroup.procs"))
        .map(|text| text.lines().filter_map(|line| line.parse().ok()).collect())
        .unwrap_or_default()
}

/// Real owner of a process: the uid of its /proc directory.
pub fn process_uid(pid: u32) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(format!("/proc/{pid}"))
        .ok()
        .map(|metadata| metadata.uid())
}

pub fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self")
        .ok()
        .map(|metadata| metadata.uid())
}

/// Listening loopback sockets held by the owned processes, with the pid
/// holding each. Socket inodes are read from /proc/<pid>/fd and matched
/// against the kernel's LISTEN table.
pub fn loopback_listeners(pids: &[u32]) -> Result<Vec<LoopbackListener>, String> {
    let mut listeners: BTreeMap<String, u32> = BTreeMap::new();
    for (pid, listener) in listening_sockets(&socket_owners(pids.iter().copied()))? {
        // A wildcard bind (0.0.0.0 / ::) also serves loopback clients;
        // many dev servers default to it.
        let host = if listener.ip.is_unspecified() {
            "127.0.0.1".to_string()
        } else if listener.ip.is_loopback() {
            format_host(&listener.ip)
        } else {
            continue;
        };
        listeners
            .entry(format!("{host}:{}", listener.port))
            .or_insert(pid);
    }
    Ok(listeners
        .into_iter()
        .map(|(address, pid)| LoopbackListener { address, pid })
        .collect())
}

struct ListenSocket {
    ip: std::net::IpAddr,
    port: u16,
    inode: u64,
    uid: u32,
    cgroup: Option<u64>,
}

// Kernel UAPI: linux/netlink.h, linux/sock_diag.h, linux/inet_diag.h.
const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const TCP_LISTEN: u32 = 10;
// Address families and protocol as the u8 fields of inet_diag_req_v2.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const NLMSG_HEADER: usize = 16;
/// sizeof(struct inet_diag_req_v2) and sizeof(struct inet_diag_msg).
const DIAG_REQUEST: usize = 56;
const DIAG_MESSAGE: usize = 72;
const REQUEST_LENGTH: u32 = 72;

/// LISTEN sockets from NETLINK_SOCK_DIAG, the interface `ss` uses. The
/// kernel filters by state, so the cost does not grow with the number of
/// established or TIME_WAIT connections the way /proc/net/tcp does.
fn listen_table() -> Result<Vec<ListenSocket>, String> {
    let mut sockets = Vec::new();
    for family in [AF_INET, AF_INET6] {
        dump_listeners(family, &mut sockets)
            .map_err(|error| format!("list listening sockets: {error}"))?;
    }
    Ok(sockets)
}

fn dump_listeners(family: u8, sockets: &mut Vec<ListenSocket>) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut request = [0u8; NLMSG_HEADER + DIAG_REQUEST];
    request[0..4].copy_from_slice(&REQUEST_LENGTH.to_ne_bytes());
    request[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    // inet_diag_req_v2: family, protocol, ext, pad, states bitmask, sockid.
    request[16] = family;
    request[17] = IPPROTO_TCP;
    request[20..24].copy_from_slice(&(1u32 << TCP_LISTEN).to_ne_bytes());
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The kernel sizes each dump datagram to the reader's buffer.
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        let Ok(received) = usize::try_from(received) else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        };
        let mut offset = 0;
        while offset + NLMSG_HEADER <= received {
            let header = &buffer[offset..offset + NLMSG_HEADER];
            let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let kind = u16::from_ne_bytes([header[4], header[5]]);
            if length < NLMSG_HEADER || offset + length > received {
                return Err(std::io::Error::other("malformed netlink message"));
            }
            let payload = &buffer[offset + NLMSG_HEADER..offset + length];
            match kind {
                NLMSG_DONE => return Ok(()),
                NLMSG_ERROR => {
                    let code = payload
                        .get(0..4)
                        .map(|bytes| i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                        .unwrap_or(-libc::EIO);
                    return Err(std::io::Error::from_raw_os_error(-code));
                }
                SOCK_DIAG_BY_FAMILY if payload.len() >= DIAG_MESSAGE => {
                    if let Some(socket) = parse_diag_message(payload) {
                        sockets.push(socket);
                    }
                }
                _ => {}
            }
            // Messages are 4-byte aligned.
            offset += (length + 3) & !3;
        }
    }
}

/// struct inet_diag_msg: family u8, state u8, timer u8, retrans u8, then
/// inet_diag_sockid (sport be16 @4, dport be16 @6, src [u8;16] @8, ...),
/// expires, rqueue, wqueue, uid u32 @64, and inode u32 @68; netlink
/// attributes follow.
fn parse_diag_message(message: &[u8]) -> Option<ListenSocket> {
    let port = u16::from_be_bytes([message[4], message[5]]);
    let source: [u8; 16] = message[8..24].try_into().ok()?;
    let ip = match message[0] {
        AF_INET => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            source[0], source[1], source[2], source[3],
        )),
        AF_INET6 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(source)),
        _ => return None,
    };
    let uid = u32::from_ne_bytes(message[64..68].try_into().ok()?);
    let inode = u32::from_ne_bytes(message[68..72].try_into().ok()?);
    Some(ListenSocket {
        ip,
        port,
        inode: u64::from(inode),
        uid,
        cgroup: cgroup_attribute(&message[DIAG_MESSAGE..]),
    })
}

/// INET_DIAG_CGROUP_ID (Linux 5.7+), sent unrequested for every full socket.
const INET_DIAG_CGROUP_ID: u16 = 21;
const NLA_TYPE_MASK: u16 = 0x3fff;

/// The cgroup id among the message's netlink attributes (struct nlattr:
/// len u16, type u16, payload, padded to 4 bytes).
fn cgroup_attribute(mut attributes: &[u8]) -> Option<u64> {
    while attributes.len() >= 4 {
        let length = usize::from(u16::from_ne_bytes([attributes[0], attributes[1]]));
        let kind = u16::from_ne_bytes([attributes[2], attributes[3]]) & NLA_TYPE_MASK;
        if length < 4 || length > attributes.len() {
            return None;
        }
        if kind == INET_DIAG_CGROUP_ID && length == 12 {
            return Some(u64::from_ne_bytes(attributes[4..12].try_into().ok()?));
        }
        attributes = attributes.get((length + 3) & !3..).unwrap_or_default();
    }
    None
}

fn format_host(ip: &std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.to_string();
            }
            format!("[{v6}]")
        }
    }
}

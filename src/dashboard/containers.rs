//! Container names for published ports, from the Docker or Podman API on its
//! local Unix socket. Best effort: without access to the socket the row
//! still says which engine forwards the port.

use serde::Deserialize;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_millis(500);
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Engine {
    Docker,
    Podman,
}

impl Engine {
    pub fn name(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    /// The engine a process belongs to: a port forwarder by its own name,
    /// a containerized process by a shim among its ancestors.
    pub fn of_forwarder(name: &str) -> Option<Self> {
        match name {
            "docker-proxy" | "rootlesskit" => Some(Self::Docker),
            "rootlessport" => Some(Self::Podman),
            _ if name.starts_with("pasta") => Some(Self::Podman),
            _ => None,
        }
    }

    pub fn of_ancestor(name: &str) -> Option<Self> {
        match name {
            "conmon" => Some(Self::Podman),
            _ if name.starts_with("containerd-shim") => Some(Self::Docker),
            _ => None,
        }
    }

    /// Engine and container id from a container's cgroup path:
    /// `.../docker-<id>.scope`, `/docker/<id>`, or `.../libpod-<id>.scope`.
    pub fn of_cgroup(path: &str) -> Option<(Self, &str)> {
        let mut parts = path.rsplit('/');
        let last = parts.next()?;
        if let Some(id) = last
            .strip_prefix("docker-")
            .and_then(|rest| rest.strip_suffix(".scope"))
        {
            return Some((Self::Docker, id));
        }
        if let Some(id) = last
            .strip_prefix("libpod-")
            .and_then(|rest| rest.strip_suffix(".scope"))
        {
            return Some((Self::Podman, id));
        }
        (parts.next() == Some("docker") && is_container_id(last)).then_some((Self::Docker, last))
    }

    fn sockets(self) -> Vec<PathBuf> {
        let (variable, runtime, system): (&str, &str, &[&str]) = match self {
            Self::Docker => (
                "DOCKER_HOST",
                "docker.sock",
                &["/run/docker.sock", "/var/run/docker.sock"],
            ),
            Self::Podman => (
                "CONTAINER_HOST",
                "podman/podman.sock",
                &["/run/podman/podman.sock"],
            ),
        };
        let mut paths = Vec::new();
        if let Some(path) = std::env::var(variable)
            .ok()
            .and_then(|value| value.strip_prefix("unix://").map(PathBuf::from))
        {
            paths.push(path);
        }
        if let Some(directory) = std::env::var_os("XDG_RUNTIME_DIR") {
            paths.push(PathBuf::from(directory).join(runtime));
        }
        paths.extend(system.iter().map(PathBuf::from));
        paths
    }
}

fn is_container_id(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    pub engine: Engine,
    pub id: String,
    pub name: String,
    pub image: String,
    pub ports: Vec<Published>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    /// Host address the port is published on; None for every address.
    pub ip: Option<IpAddr>,
    pub host_port: u16,
    pub container_port: u16,
}

#[derive(Debug)]
pub enum ContainerError {
    NoSocket(Engine),
    Io(std::io::Error),
    Status(String),
    TooLarge,
    Decode(serde_json::Error),
}

impl std::fmt::Display for ContainerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSocket(engine) => write!(formatter, "no {} socket found", engine.name()),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Status(line) => write!(formatter, "API answered {line:?}"),
            Self::TooLarge => write!(formatter, "API response too large"),
            Self::Decode(error) => write!(formatter, "unreadable API response: {error}"),
        }
    }
}

impl From<std::io::Error> for ContainerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ContainerError {
    fn from(error: serde_json::Error) -> Self {
        Self::Decode(error)
    }
}

#[derive(Deserialize)]
struct ApiContainer {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "Ports", default)]
    ports: Vec<ApiPort>,
}

#[derive(Deserialize)]
struct ApiPort {
    #[serde(rename = "IP", default)]
    ip: Option<String>,
    #[serde(rename = "PrivatePort", default)]
    private_port: u16,
    #[serde(rename = "PublicPort", default)]
    public_port: Option<u16>,
    #[serde(rename = "Type", default)]
    kind: String,
}

/// Running containers of `engine`, from the first socket that exists.
pub fn list(engine: Engine) -> Result<Vec<Container>, ContainerError> {
    let socket = engine
        .sockets()
        .into_iter()
        .find(|path| {
            use std::os::unix::fs::FileTypeExt as _;
            std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
        })
        .ok_or(ContainerError::NoSocket(engine))?;
    let body = get(&socket, "/containers/json")?;
    let containers: Vec<ApiContainer> = serde_json::from_slice(&body)?;
    Ok(containers
        .into_iter()
        .map(|container| Container {
            engine,
            id: container.id,
            name: container
                .names
                .first()
                .map(|name| name.trim_start_matches('/').to_string())
                .unwrap_or_default(),
            image: container.image,
            ports: container
                .ports
                .iter()
                .filter(|port| port.kind == "tcp")
                .filter_map(|port| {
                    Some(Published {
                        ip: port
                            .ip
                            .as_deref()
                            .and_then(|ip| ip.parse::<IpAddr>().ok())
                            .filter(|ip| !ip.is_unspecified()),
                        host_port: port.public_port?,
                        container_port: port.private_port,
                    })
                })
                .collect(),
        })
        .collect())
}

/// HTTP/1.0 GET: the server closes the connection after an unchunked body.
fn get(socket: &std::path::Path, path: &str) -> Result<Vec<u8>, ContainerError> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)?;
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(ContainerError::TooLarge);
    }
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| ContainerError::Status("no HTTP header".to_string()))?;
    let status_line = response[..head_end]
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim_end().to_string())
        .unwrap_or_default();
    if status_line.split_ascii_whitespace().nth(1) != Some("200") {
        return Err(ContainerError::Status(status_line));
    }
    Ok(response.split_off(head_end + 4))
}

/// The container publishing `port` on one of `addresses`, with the port it
/// maps to inside the container.
pub fn published<'a>(
    containers: &'a [Container],
    port: u16,
    addresses: &[IpAddr],
) -> Option<(&'a Container, u16)> {
    containers.iter().find_map(|container| {
        container
            .ports
            .iter()
            .find(|published| {
                published.host_port == port
                    && published.ip.map_or(true, |ip| {
                        addresses
                            .iter()
                            .any(|address| *address == ip || address.is_unspecified())
                    })
            })
            .map(|published| (container, published.container_port))
    })
}

/// The container whose id starts with `id` (a full id from a cgroup path).
pub fn by_id<'a>(containers: &'a [Container], engine: Engine, id: &str) -> Option<&'a Container> {
    containers
        .iter()
        .find(|container| {
            container.engine == engine && !container.id.is_empty() && id.starts_with(&container.id)
        })
        .or_else(|| {
            containers
                .iter()
                .find(|container| container.engine == engine && container.id.starts_with(id))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_from_cgroup_paths() {
        let id = "a".repeat(64);
        assert_eq!(
            Engine::of_cgroup(&format!("/system.slice/docker-{id}.scope")),
            Some((Engine::Docker, id.as_str()))
        );
        assert_eq!(
            Engine::of_cgroup(&format!("/docker/{id}")),
            Some((Engine::Docker, id.as_str()))
        );
        assert_eq!(
            Engine::of_cgroup(&format!("/machine.slice/libpod-{id}.scope")),
            Some((Engine::Podman, id.as_str()))
        );
        assert_eq!(Engine::of_cgroup("/system.slice/sshd.service"), None);
    }

    #[test]
    fn matches_published_ports_by_address() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let containers = [Container {
            engine: Engine::Docker,
            id: "abc".to_string(),
            name: "silverbullet".to_string(),
            image: "silverbullet".to_string(),
            ports: vec![Published {
                ip: Some(loopback),
                host_port: 3030,
                container_port: 3000,
            }],
        }];
        let found = published(&containers, 3030, &[loopback]);
        assert_eq!(
            found.map(|(container, port)| (container.name.as_str(), port)),
            Some(("silverbullet", 3000))
        );
        let tailnet: IpAddr = "100.64.0.1".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(published(&containers, 3030, &[tailnet]).is_none());
        assert!(published(&containers, 3031, &[loopback]).is_none());
    }
}

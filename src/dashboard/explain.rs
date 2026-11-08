//! What a listening port is for, from fixed offline rules. Every row gets the
//! explanations that apply, most specific first: a Porthmeus session or
//! Tailscale Serve route, a container, a systemd unit, a known program, then
//! the port's conventional use.

use super::containers::Engine;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Session,
    Serve,
    /// tailscaled's own listener for a Serve port.
    Frontend,
    Container,
    Unit,
    Program,
    Port,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation {
    pub source: Source,
    /// Short enough for the table.
    pub text: String,
    /// Extra facts for the detail line.
    pub detail: Option<String>,
}

/// A container behind the port, as far as it is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerFact<'a> {
    pub engine: Engine,
    /// The process forwards a published port (docker-proxy, rootlesskit)
    /// rather than running inside the container.
    pub forwarder: bool,
    pub name: Option<&'a str>,
    pub image: Option<&'a str>,
    pub container_port: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitFact<'a> {
    pub name: &'a str,
    pub user: bool,
}

/// Everything known about one row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts<'a> {
    pub port: u16,
    pub session: bool,
    pub served: bool,
    /// tailscaled listening on a port its Serve config publishes.
    pub serve_frontend: bool,
    pub container: Option<ContainerFact<'a>>,
    pub unit: Option<UnitFact<'a>>,
    /// Kernel process name (comm), empty when unknown.
    pub name: &'a str,
    /// Full command line, empty when unknown.
    pub command: &'a str,
}

pub fn explain(facts: &Facts<'_>) -> Vec<Explanation> {
    let mut found = Vec::new();
    if facts.session {
        found.push(plain(Source::Session, "Porthmeus session"));
    } else if facts.serve_frontend {
        found.push(plain(Source::Frontend, "Tailscale Serve frontend"));
    } else if facts.served {
        found.push(plain(Source::Serve, "Tailscale Serve"));
    }
    if let Some(container) = facts.container {
        found.push(container_explanation(&container));
    }
    if let Some(unit) = facts.unit {
        found.push(Explanation {
            source: Source::Unit,
            text: if unit.user {
                format!("{} (user)", unit.name)
            } else {
                unit.name.to_string()
            },
            detail: Some(
                if unit.user {
                    "systemd user unit"
                } else {
                    "systemd unit"
                }
                .to_string(),
            ),
        });
    }
    if let Some(label) = program_label(facts.name, facts.command) {
        found.push(plain(Source::Program, label));
    }
    if let Some(label) = port_label(facts.port) {
        found.push(Explanation {
            source: Source::Port,
            text: format!("likely {label}"),
            detail: None,
        });
    }
    found
}

fn plain(source: Source, text: &str) -> Explanation {
    Explanation {
        source,
        text: text.to_string(),
        detail: None,
    }
}

fn container_explanation(container: &ContainerFact<'_>) -> Explanation {
    let engine = container.engine.name();
    let text = match (container.name, container.forwarder) {
        (Some(name), _) => format!("{engine} {name}"),
        (None, true) => format!("{engine} published port"),
        (None, false) => format!("{engine} container"),
    };
    let mut parts = Vec::new();
    if let Some(port) = container.container_port {
        parts.push(format!("container port {port}"));
    }
    if let Some(image) = container.image.filter(|image| !image.is_empty()) {
        parts.push(format!("image {image}"));
    }
    if container.forwarder {
        parts.push(format!("forwarded by the {engine} engine"));
    }
    Explanation {
        source: Source::Container,
        text,
        detail: (!parts.is_empty()).then(|| parts.join(", ")),
    }
}

/// A program, optionally only with `argument` among its arguments.
struct ProgramRule {
    program: &'static str,
    argument: &'static str,
    label: &'static str,
}

const fn rule(program: &'static str, argument: &'static str, label: &'static str) -> ProgramRule {
    ProgramRule {
        program,
        argument,
        label,
    }
}

/// First match wins: specific arguments before a program's catch-all.
const PROGRAMS: &[ProgramRule] = &[
    rule("node", "vite", "Vite dev server"),
    rule("node", "next", "Next.js dev server"),
    rule("node", "astro", "Astro dev server"),
    rule("node", "nuxt", "Nuxt dev server"),
    rule("node", "nuxi", "Nuxt dev server"),
    rule("node", "remix", "Remix dev server"),
    rule("node", "webpack", "webpack dev server"),
    rule("node", "storybook", "Storybook"),
    rule("node", "wrangler", "Wrangler dev server"),
    rule("node", "vitepress", "VitePress dev server"),
    rule("node", "eleventy", "Eleventy dev server"),
    rule("node", "--inspect", "Node.js with inspector"),
    rule("node", "", "Node.js server"),
    rule("bun", "vite", "Vite dev server"),
    rule("bun", "next", "Next.js dev server"),
    rule("bun", "", "Bun server"),
    rule("deno", "", "Deno server"),
    rule("vite", "", "Vite dev server"),
    rule("next-server", "", "Next.js server"),
    rule("workerd", "", "Cloudflare workerd"),
    rule("esbuild", "", "esbuild serve"),
    rule("python", "http.server", "Python http.server"),
    rule("python", "uvicorn", "Uvicorn ASGI server"),
    rule("python", "gunicorn", "Gunicorn server"),
    rule("python", "runserver", "Django dev server"),
    rule("python", "flask", "Flask dev server"),
    rule("python", "jupyter", "Jupyter server"),
    rule("python", "jupyter-lab", "Jupyter server"),
    rule("python", "mkdocs", "MkDocs dev server"),
    rule("python", "", "Python server"),
    rule("uvicorn", "", "Uvicorn ASGI server"),
    rule("gunicorn", "", "Gunicorn server"),
    rule("jupyter-lab", "", "Jupyter server"),
    rule("ruby", "rails", "Rails server"),
    rule("ruby", "jekyll", "Jekyll dev server"),
    rule("puma", "", "Puma (Rails) server"),
    rule("php", "-S", "PHP built-in server"),
    rule("php-fpm", "", "PHP-FPM"),
    rule("hugo", "", "Hugo server"),
    rule("zola", "", "Zola server"),
    rule("trunk", "", "Trunk dev server"),
    rule("java", "", "Java server"),
    rule("dotnet", "", ".NET server"),
    rule("postgres", "", "PostgreSQL"),
    rule("postmaster", "", "PostgreSQL"),
    rule("mysqld", "", "MySQL"),
    rule("mariadbd", "", "MariaDB"),
    rule("redis-server", "", "Redis"),
    rule("valkey-server", "", "Valkey"),
    rule("mongod", "", "MongoDB"),
    rule("memcached", "", "memcached"),
    rule("clickhouse-serv", "", "ClickHouse"),
    rule("meilisearch", "", "Meilisearch"),
    rule("sshd", "", "SSH server"),
    rule("sshd-session", "", "SSH server"),
    rule("tailscaled", "", "Tailscale daemon"),
    rule("syncthing", "", "Syncthing"),
    rule("socat", "", "socat relay"),
    rule("nginx", "", "nginx"),
    rule("caddy", "", "Caddy"),
    rule("httpd", "", "Apache httpd"),
    rule("apache2", "", "Apache httpd"),
    rule("haproxy", "", "HAProxy"),
    rule("traefik", "", "Traefik"),
    rule("smbd", "", "Samba file sharing"),
    rule("cupsd", "", "CUPS printing"),
    rule("dnsmasq", "", "dnsmasq DNS"),
    rule("unbound", "", "Unbound DNS"),
    rule("AdGuardHome", "", "AdGuard Home DNS"),
    rule("adguardhome", "", "AdGuard Home DNS"),
    rule("systemd-resolve", "", "systemd-resolved DNS"),
    rule("systemd", "", "systemd socket activation"),
    rule("avahi-daemon", "", "Avahi mDNS"),
    rule("ollama", "", "Ollama"),
    rule("code-server", "", "code-server"),
    rule("openvscode-serv", "", "OpenVSCode Server"),
    rule("grafana", "", "Grafana"),
    rule("grafana-server", "", "Grafana"),
    rule("prometheus", "", "Prometheus"),
    rule("node_exporter", "", "Prometheus node exporter"),
    rule("jellyfin", "", "Jellyfin"),
    rule("harmonia", "", "Nix binary cache"),
    rule("nix-serve", "", "Nix binary cache"),
    rule("openrgb", "", "OpenRGB server"),
    rule("kdeconnectd", "", "KDE Connect"),
    rule("cockpit-ws", "", "Cockpit"),
    rule("docker-proxy", "", "Docker port forward"),
    rule("rootlesskit", "", "rootless Docker port forward"),
    rule("rootlessport", "", "rootless Podman port forward"),
    rule("dockerd", "", "Docker daemon"),
    rule("containerd", "", "containerd"),
    rule("chrome", "--remote-debugging-port", "Chrome DevTools"),
    rule("chromium", "--remote-debugging-port", "Chromium DevTools"),
    rule("porthmeus", "", "Porthmeus bridge"),
];

/// The label of the first rule whose program is the kernel name or the
/// command's program, and whose argument (if any) is one of the command's
/// arguments.
pub fn program_label(name: &str, command: &str) -> Option<&'static str> {
    // Retitled processes read `sshd: user [priv]`.
    let program = command
        .split_ascii_whitespace()
        .next()
        .map(base_name)
        .map(|program| program.strip_suffix(':').unwrap_or(program))
        .unwrap_or_default();
    PROGRAMS
        .iter()
        .find(|rule| {
            let program_matches =
                same_program(name, rule.program) || same_program(program, rule.program);
            program_matches
                && (rule.argument.is_empty()
                    || command
                        .split_ascii_whitespace()
                        .skip(1)
                        .any(|word| argument_matches(word, rule.argument)))
        })
        .map(|rule| rule.label)
}

/// `python3.12` and `node22` are `python` and `node`.
fn same_program(candidate: &str, program: &str) -> bool {
    candidate.strip_prefix(program).is_some_and(|rest| {
        rest.bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    })
}

/// `vite`, `/x/node_modules/.bin/vite`, `vite.js`, and `--port=1` style
/// flags against `--port`.
fn argument_matches(word: &str, argument: &str) -> bool {
    if argument.starts_with('-') {
        return word == argument
            || word
                .strip_prefix(argument)
                .is_some_and(|rest| rest.starts_with('='));
    }
    let base = base_name(word);
    base == argument
        || base
            .split_once('.')
            .is_some_and(|(stem, _)| stem == argument && !argument.contains('.'))
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Conventional uses of well-known and common development ports.
const PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (111, "RPC portmapper"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB file sharing"),
    (548, "AFP file sharing"),
    (587, "SMTP submission"),
    (631, "IPP printing"),
    (853, "DNS over TLS"),
    (993, "IMAPS"),
    (1080, "SOCKS proxy"),
    (1433, "SQL Server"),
    (1883, "MQTT"),
    (2049, "NFS"),
    (2375, "Docker API"),
    (2376, "Docker API (TLS)"),
    (3000, "a dev server"),
    (3306, "MySQL"),
    (3389, "Remote Desktop"),
    (4200, "Angular dev server"),
    (4321, "Astro dev server"),
    (5000, "a dev server"),
    (5173, "Vite dev server"),
    (5432, "PostgreSQL"),
    (5672, "AMQP"),
    (5900, "VNC"),
    (6006, "Storybook"),
    (6379, "Redis"),
    (6443, "Kubernetes API"),
    (7700, "Meilisearch"),
    (8000, "an HTTP dev server"),
    (8080, "HTTP (alternate)"),
    (8384, "Syncthing GUI"),
    (8443, "HTTPS (alternate)"),
    (9000, "an HTTP server"),
    (9090, "Prometheus or Cockpit"),
    (9100, "Prometheus node exporter"),
    (9229, "Node.js inspector"),
    (9418, "git daemon"),
    (11434, "Ollama"),
    (22000, "Syncthing sync"),
    (27017, "MongoDB"),
];

pub fn port_label(port: u16) -> Option<&'static str> {
    PORTS
        .binary_search_by_key(&port, |(known, _)| *known)
        .ok()
        .map(|index| PORTS[index].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_sorted_for_binary_search() {
        assert!(PORTS.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(port_label(22), Some("SSH"));
        assert_eq!(port_label(23), None);
    }

    #[test]
    fn recognizes_programs_by_name_and_arguments() {
        let label = |name, command| program_label(name, command);
        assert_eq!(
            label("node", "node /p/node_modules/.bin/vite --host"),
            Some("Vite dev server")
        );
        assert_eq!(
            label("python3", "python3 -m http.server 8000"),
            Some("Python http.server")
        );
        assert_eq!(
            label("python3.12", "/usr/bin/python3.12 manage.py runserver"),
            Some("Django dev server")
        );
        assert_eq!(
            label("node", "node --inspect=9229 server.js"),
            Some("Node.js with inspector")
        );
        assert_eq!(label("node", "node nextcloud.js"), Some("Node.js server"));
        assert_eq!(label("sshd", ""), Some("SSH server"));
        assert_eq!(label("unknownd", "unknownd"), None);
    }

    #[test]
    fn rules_apply_in_priority_order() {
        let facts = Facts {
            port: 3030,
            served: true,
            container: Some(ContainerFact {
                engine: Engine::Docker,
                forwarder: true,
                name: Some("silverbullet"),
                image: Some("silverbullet:latest"),
                container_port: Some(3000),
            }),
            unit: Some(UnitFact {
                name: "docker.service",
                user: true,
            }),
            name: "rootlesskit",
            command: "rootlesskit --net=slirp4netns",
            ..Facts::default()
        };
        let sources: Vec<Source> = explain(&facts).iter().map(|found| found.source).collect();
        assert_eq!(
            sources,
            [
                Source::Serve,
                Source::Container,
                Source::Unit,
                Source::Program
            ]
        );
        assert_eq!(explain(&facts)[1].text, "docker silverbullet");
    }

    #[test]
    fn unknown_port_without_facts_has_no_explanation() {
        assert!(explain(&Facts {
            port: 47_123,
            ..Facts::default()
        })
        .is_empty());
    }
}

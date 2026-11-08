//! The dashboard (`porthmeus` with no command): every listening TCP port on
//! the machine, what it is for, and a key to stop the ones this user owns.

mod containers;
mod explain;
mod terminal;
mod view;

use crate::discovery::{self, Listener, ProcessInfo};
use crate::signal::Events;
use crate::style::{print_error, sanitize, Style};
use crate::tailscale;
use containers::{Container, Engine};
use explain::{ContainerFact, Explanation, Facts, UnitFact};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
/// Safety net for changes the listener fingerprint cannot see.
const FULL_SCAN_INTERVAL: Duration = Duration::from_secs(30);
/// Re-scan shortly after a stop so the row disappears promptly.
const AFTER_STOP_REFRESH: Duration = Duration::from_millis(400);
/// Ancestors examined for a container shim; real trees are far shallower.
const MAX_ANCESTRY: usize = 64;

/// Which process holds a row's socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Owner {
    /// Read from the process's own descriptors.
    Exact(u32),
    /// The main process of the socket's cgroup: the descriptors are
    /// unreadable without root, so this is a well-founded guess.
    Inferred(u32),
    Unknown,
}

impl Owner {
    fn pid(self) -> Option<u32> {
        match self {
            Self::Exact(pid) | Self::Inferred(pid) => Some(pid),
            Self::Unknown => None,
        }
    }
}

/// Identity of a row across refreshes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RowKey {
    port: u16,
    owner: Owner,
    uid: Option<u32>,
    /// Keeps sockets of unknown owners in different cgroups apart.
    cgroup: Option<u64>,
}

/// One port and its owner; a Porthmeus session is one row for its dev
/// server's ports.
#[derive(Clone, Debug)]
struct Row {
    key: RowKey,
    /// A session's other dev server ports.
    more_ports: Vec<u16>,
    addresses: Vec<IpAddr>,
    user: String,
    mine: bool,
    /// Signal the whole process group: set only when the process leads its
    /// own group, so a parent shell is never hit.
    group: bool,
    /// A process that Tailscale Serve proxies to and whose descendants
    /// listen. It stops its own tree on SIGTERM.
    session: bool,
    /// Program name for the table; empty when unknown.
    program: String,
    command: String,
    /// The process the explanation describes: a session's dev server, or the
    /// owner itself. Kernel name and command line.
    subject_name: String,
    subject_command: String,
    /// Working directory, `~`-relative, where readable.
    dir: String,
    cgroup_path: Option<String>,
    /// Container engine, and whether the process only forwards a published
    /// port.
    engine: Option<(Engine, bool)>,
    container_id: Option<String>,
    /// Container name, once the engine's API named it.
    container: Option<String>,
    urls: Vec<String>,
    frontend: bool,
    why: Vec<Explanation>,
}

impl Row {
    fn port(&self) -> u16 {
        self.key.port
    }

    fn unit(&self) -> Option<UnitFact<'_>> {
        self.cgroup_path.as_deref().and_then(unit_of)
    }

    /// The pid `x` may signal, or why it may not.
    fn stop_target(&self, own_pid: u32) -> Result<u32, String> {
        let port = self.port();
        if !self.mine {
            return Err(format!(
                ":{port} belongs to {}; Porthmeus stops only your own processes.",
                self.user
            ));
        }
        let pid = match self.key.owner {
            Owner::Exact(pid) => pid,
            Owner::Inferred(_) | Owner::Unknown => {
                return Err(format!(
                    "The process holding :{port} hides its sockets; stop it by other means."
                ))
            }
        };
        if let Some((engine, _)) = self.engine {
            let engine = engine.name();
            return Err(match &self.container {
                Some(name) => format!(":{port} belongs to a container. Run: {engine} stop {name}"),
                None => format!(":{port} belongs to a {engine} container; stop it with {engine}."),
            });
        }
        if pid == own_pid || pid <= 1 {
            return Err(format!("Refusing to signal pid {pid}."));
        }
        Ok(pid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    Stop,
    Kill,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tone {
    Info,
    Good,
    Warn,
    Bad,
}

struct State {
    rows: Vec<Row>,
    /// Indices into `rows` currently shown.
    visible: Vec<usize>,
    only_mine: bool,
    /// Position in `visible`.
    selected: usize,
    offset: usize,
    tailscale_cli: Option<String>,
    routes: Vec<(u16, String)>,
    /// Ports Tailscale Serve publishes on the tailnet.
    frontends: Vec<u16>,
    routes_key: BTreeSet<(Option<u32>, u16)>,
    tailscale_note: Option<String>,
    containers: Vec<Container>,
    containers_key: BTreeSet<(Engine, u16)>,
    container_note: Option<String>,
    cgroups: HashMap<u64, String>,
    missing_cgroups: BTreeSet<u64>,
    users: HashMap<u32, String>,
    missing_users: BTreeSet<u32>,
    own_uid: Option<u32>,
    own_pid: u32,
    host: String,
    home: String,
    message: Option<(Tone, String)>,
    pending: Option<(u32, Pending)>,
    stopped: BTreeSet<u32>,
    signature: String,
    scanned_at: Option<Instant>,
    force_scan: bool,
    scan_error: Option<String>,
}

pub fn run(tailscale_cli: Option<&str>) -> i32 {
    let mut state = State::new(tailscale_cli);
    let mut stdout = std::io::stdout();
    // Pipes and TERM=dumb get the plain table; only a capable terminal is drawn.
    if !(std::io::stdin().is_terminal() && Style::stdout().is_terminal()) {
        state.refresh();
        if let Some(error) = &state.scan_error {
            print_error(error);
            return 1;
        }
        return match stdout
            .write_all(view::table(&state).as_bytes())
            .and_then(|()| stdout.flush())
        {
            Ok(()) => 0,
            Err(error) => {
                print_error(&error.to_string());
                1
            }
        };
    }
    let events = match Events::install(&[libc::SIGWINCH]) {
        Ok(events) => events,
        Err(error) => {
            print_error(&error);
            return 1;
        }
    };
    let terminal = match terminal::Raw::enter() {
        Ok(terminal) => terminal,
        Err(error) => {
            print_error(&error);
            return 1;
        }
    };
    let outcome = interact(&events, &mut state, &mut stdout);
    drop(terminal);
    match outcome {
        Ok(()) => 0,
        Err(error) => {
            print_error(&error);
            1
        }
    }
}

fn interact(events: &Events, state: &mut State, stdout: &mut dyn Write) -> Result<(), String> {
    let style = Style::terminal();
    // The first frame shows the loading state while the first scan runs.
    draw(stdout, state, style)?;
    state.refresh();
    let mut next_refresh = Instant::now() + REFRESH_INTERVAL;
    let mut input = [0u8; 64];
    loop {
        draw(stdout, state, style)?;
        let timeout = next_refresh.saturating_duration_since(Instant::now());
        let [input_ready, _] = events.wait_with(&[libc::STDIN_FILENO], Some(timeout));
        if events.take_signal().is_some() {
            return Ok(());
        }
        if input_ready {
            let read =
                unsafe { libc::read(libc::STDIN_FILENO, input.as_mut_ptr().cast(), input.len()) };
            let Ok(read) = usize::try_from(read) else {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("read terminal: {error}"));
            };
            if read == 0 {
                return Ok(());
            }
            let (_, height) = terminal::size();
            for key in keys(&input[..read]) {
                match state.handle(key, view::page_size(height)) {
                    Action::Quit => return Ok(()),
                    Action::Refresh => {
                        state.force_scan = true;
                        next_refresh = Instant::now();
                    }
                    Action::RefreshSoon => {
                        state.force_scan = true;
                        next_refresh = Instant::now() + AFTER_STOP_REFRESH;
                    }
                    Action::None => {}
                }
            }
        }
        if Instant::now() >= next_refresh {
            state.refresh();
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}

fn draw(stdout: &mut dyn Write, state: &mut State, style: Style) -> Result<(), String> {
    let (width, height) = terminal::size();
    let frame = view::render(state, width, height, style);
    stdout
        .write_all(frame.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("write terminal: {error}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Stop,
    Refresh,
    Mine,
    Yes,
    Quit,
    Escape,
    Other,
}

fn keys(bytes: &[u8]) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let rest = &bytes[index..];
        let (key, used) = match rest {
            [0x1b, b'[' | b'O', b'A', ..] => (Key::Up, 3),
            [0x1b, b'[' | b'O', b'B', ..] => (Key::Down, 3),
            [0x1b, b'[' | b'O', b'H', ..] => (Key::Home, 3),
            [0x1b, b'[' | b'O', b'F', ..] => (Key::End, 3),
            [0x1b, b'[', b'3', b'~', ..] => (Key::Stop, 4),
            [0x1b, b'[', b'5', b'~', ..] => (Key::PageUp, 4),
            [0x1b, b'[', b'6', b'~', ..] => (Key::PageDown, 4),
            [0x1b, b'[', ..] => (Key::Other, csi_length(rest)),
            [0x1b, ..] => (Key::Escape, 1),
            [b'k', ..] => (Key::Up, 1),
            [b'j', ..] => (Key::Down, 1),
            [b'g', ..] => (Key::Home, 1),
            [b'G', ..] => (Key::End, 1),
            [b'x' | b'd', ..] => (Key::Stop, 1),
            [b'r', ..] => (Key::Refresh, 1),
            [b'm', ..] => (Key::Mine, 1),
            [b'y' | b'Y', ..] => (Key::Yes, 1),
            [b'q' | 0x03 | 0x04, ..] => (Key::Quit, 1),
            _ => (Key::Other, 1),
        };
        keys.push(key);
        index += used;
    }
    keys
}

/// Length of an unrecognized CSI sequence: ESC [ params final-byte.
fn csi_length(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .skip(2)
        .position(|byte| (0x40..=0x7e).contains(byte))
        .map(|position| position + 3)
        .unwrap_or(bytes.len())
}

enum Action {
    None,
    Refresh,
    RefreshSoon,
    Quit,
}

impl State {
    fn new(tailscale_cli: Option<&str>) -> Self {
        Self {
            rows: Vec::new(),
            visible: Vec::new(),
            only_mine: false,
            selected: 0,
            offset: 0,
            tailscale_cli: tailscale_cli.map(str::to_string),
            routes: Vec::new(),
            frontends: Vec::new(),
            routes_key: BTreeSet::new(),
            tailscale_note: None,
            containers: Vec::new(),
            containers_key: BTreeSet::new(),
            container_note: None,
            cgroups: HashMap::new(),
            missing_cgroups: BTreeSet::new(),
            users: HashMap::new(),
            missing_users: BTreeSet::new(),
            own_uid: discovery::current_uid(),
            own_pid: std::process::id(),
            host: host_name(),
            home: std::env::var("HOME").unwrap_or_default(),
            message: None,
            pending: None,
            stopped: BTreeSet::new(),
            signature: String::new(),
            scanned_at: None,
            force_scan: true,
            scan_error: None,
        }
    }

    fn selected_row(&self) -> Option<&Row> {
        self.visible
            .get(self.selected)
            .and_then(|index| self.rows.get(*index))
    }

    /// Rescans processes only when the kernel's listener list changed, a
    /// rescan was requested, or the last one is older than FULL_SCAN_INTERVAL.
    fn refresh(&mut self) {
        // A failed scan keeps the last rows on screen and says why.
        let signature = match discovery::listen_signature() {
            Ok(signature) => signature,
            Err(error) => {
                self.scan_error = Some(error);
                return;
            }
        };
        let fresh = self
            .scanned_at
            .is_some_and(|at| at.elapsed() < FULL_SCAN_INTERVAL);
        if !self.force_scan && fresh && signature == self.signature {
            return;
        }
        let listeners = match discovery::all_listeners() {
            Ok(listeners) => listeners,
            Err(error) => {
                self.scan_error = Some(error);
                return;
            }
        };
        self.scan_error = None;
        self.signature = signature;
        self.scanned_at = Some(Instant::now());
        self.force_scan = false;
        let processes = discovery::process_table();
        let by_pid: HashMap<u32, &ProcessInfo> = processes
            .iter()
            .map(|process| (process.pid, process))
            .collect();
        self.learn_cgroups(&listeners);
        self.learn_users(&listeners);
        self.load_routes(&listeners);
        let inferred = self.infer_owners(&listeners, &by_pid);
        let selected_key = self.selected_row().map(|row| row.key.clone());
        let mut rows = self.group(&listeners, &inferred, &processes, &by_pid);
        self.load_containers(&rows);
        let pids: Vec<u32> = rows
            .iter()
            .filter_map(|row| match row.key.owner {
                Owner::Exact(pid) => Some(pid),
                Owner::Inferred(_) | Owner::Unknown => None,
            })
            .collect();
        let directories = discovery::working_directories(&pids);
        for row in &mut rows {
            if let Some(dir) = row.key.owner.pid().and_then(|pid| directories.get(&pid)) {
                row.dir = sanitize(&home_relative(dir, &self.home));
            }
            describe(row, &self.containers);
        }
        self.rows = rows;
        let live: BTreeSet<u32> = processes.iter().map(|process| process.pid).collect();
        self.stopped.retain(|pid| live.contains(pid));
        if let Some((pid, _)) = self.pending {
            if !self
                .rows
                .iter()
                .any(|row| row.key.owner == Owner::Exact(pid))
            {
                self.pending = None;
            }
        }
        self.filter(selected_key);
    }

    /// Recomputes the visible rows, keeping the selection on `key` if shown.
    fn filter(&mut self, key: Option<RowKey>) {
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| !self.only_mine || row.mine)
            .map(|(index, _)| index)
            .collect();
        self.selected = key
            .and_then(|key| {
                self.visible
                    .iter()
                    .position(|index| self.rows[*index].key == key)
            })
            .unwrap_or(self.selected)
            .min(self.visible.len().saturating_sub(1));
    }

    /// cgroup paths for the listeners' cgroup ids; the tree is walked again
    /// only when an id appears that the last walk did not know.
    fn learn_cgroups(&mut self, listeners: &[Listener]) {
        let unknown = listeners
            .iter()
            .filter_map(|listener| listener.cgroup)
            .any(|id| !self.cgroups.contains_key(&id) && !self.missing_cgroups.contains(&id));
        if !unknown {
            return;
        }
        self.cgroups = discovery::cgroup_index();
        self.missing_cgroups = listeners
            .iter()
            .filter_map(|listener| listener.cgroup)
            .filter(|id| !self.cgroups.contains_key(id))
            .collect();
    }

    fn learn_users(&mut self, listeners: &[Listener]) {
        let unknown = listeners
            .iter()
            .filter_map(|listener| listener.uid)
            .any(|uid| !self.users.contains_key(&uid) && !self.missing_users.contains(&uid));
        if !unknown {
            return;
        }
        self.users = discovery::user_names();
        if let (Some(uid), Ok(name)) = (self.own_uid, std::env::var("USER")) {
            if !name.is_empty() {
                self.users.entry(uid).or_insert(name);
            }
        }
        let missing: BTreeSet<u32> = listeners
            .iter()
            .filter_map(|listener| listener.uid)
            .filter(|uid| !self.users.contains_key(uid))
            .collect();
        for uid in missing
            .iter()
            .filter(|uid| discovery::DYNAMIC_USERS.contains(uid))
        {
            if let Some(name) = discovery::dynamic_user_name(*uid) {
                self.users.insert(*uid, sanitize(&name));
            }
        }
        self.missing_users = missing
            .into_iter()
            .filter(|uid| !self.users.contains_key(uid))
            .collect();
    }

    /// Serve status only changes when listeners do; skip Tailscale otherwise.
    fn load_routes(&mut self, listeners: &[Listener]) {
        let key: BTreeSet<(Option<u32>, u16)> = listeners
            .iter()
            .map(|listener| (listener.pid, listener.port))
            .collect();
        if key == self.routes_key && self.tailscale_note.is_none() {
            return;
        }
        let loaded = tailscale::Tailscale::connect(self.tailscale_cli.as_deref())
            .and_then(|tailscale| tailscale.serve_config());
        match loaded {
            Ok(config) => {
                self.routes = config.loopback_routes();
                self.frontends.clear();
                frontend_ports(&config, &mut self.frontends);
                self.tailscale_note = None;
            }
            Err(error) => {
                self.routes.clear();
                self.frontends.clear();
                self.tailscale_note = Some(error);
            }
        }
        self.routes_key = key;
    }

    /// Main processes of the cgroups holding sockets whose holder is hidden.
    fn infer_owners(
        &self,
        listeners: &[Listener],
        by_pid: &HashMap<u32, &ProcessInfo>,
    ) -> HashMap<(u64, u32), u32> {
        let mut inferred = HashMap::new();
        let mut tried = BTreeSet::new();
        for listener in listeners.iter().filter(|listener| listener.pid.is_none()) {
            let (Some(cgroup), Some(uid)) = (listener.cgroup, listener.uid) else {
                continue;
            };
            if !tried.insert((cgroup, uid)) {
                continue;
            }
            let Some(path) = self.cgroups.get(&cgroup) else {
                continue;
            };
            if let Some(pid) = infer_owner(path, uid, by_pid) {
                inferred.insert((cgroup, uid), pid);
            }
        }
        inferred
    }

    /// Builds the rows: Porthmeus sessions first, then one row per port and
    /// owner.
    fn group(
        &self,
        listeners: &[Listener],
        inferred: &HashMap<(u64, u32), u32>,
        processes: &[ProcessInfo],
        by_pid: &HashMap<u32, &ProcessInfo>,
    ) -> Vec<Row> {
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for process in processes {
            if process.ppid != process.pid {
                children.entry(process.ppid).or_default().push(process.pid);
            }
        }
        let mut by_owner: HashMap<u32, Vec<&Listener>> = HashMap::new();
        for listener in listeners {
            if let Some(pid) = listener.pid.filter(|pid| *pid != self.own_pid) {
                by_owner.entry(pid).or_default().push(listener);
            }
        }
        let urls_for = |listeners: &[&Listener]| -> Vec<String> {
            let mut urls: Vec<String> = listeners
                .iter()
                .filter(|listener| reachable_locally(listener.ip))
                .flat_map(|listener| {
                    self.routes
                        .iter()
                        .filter(move |(port, _)| *port == listener.port)
                        .map(|(_, url)| url.clone())
                })
                .collect();
            urls.sort();
            urls.dedup();
            urls
        };

        let mut rows = Vec::new();
        let mut consumed: BTreeSet<u32> = BTreeSet::new();
        // A served listener whose descendants also listen is a proxy in front
        // of them (Porthmeus): one row for the whole tree.
        let mut served: Vec<u32> = by_owner
            .iter()
            .filter(|(_, owned)| !urls_for(owned).is_empty())
            .map(|(pid, _)| *pid)
            .collect();
        served.sort_unstable();
        for pid in served {
            let mut inner: Vec<&Listener> = descendants(pid, &children)
                .into_iter()
                .filter(|child| !consumed.contains(child))
                .flat_map(|child| by_owner.get(&child).into_iter().flatten().copied())
                .collect();
            if inner.is_empty() {
                continue;
            }
            inner.sort_by_key(|listener| (listener.port, listener.pid));
            let Some(first) = inner.first().copied() else {
                continue;
            };
            consumed.insert(pid);
            consumed.extend(inner.iter().filter_map(|listener| listener.pid));
            let own = by_owner.get(&pid).map(Vec::as_slice).unwrap_or_default();
            let uid = own.first().and_then(|listener| listener.uid);
            let process = by_pid.get(&pid).copied();
            let subject = first.pid.and_then(|child| by_pid.get(&child).copied());
            let mut more_ports: Vec<u16> = inner
                .iter()
                .map(|listener| listener.port)
                .filter(|port| *port != first.port)
                .collect();
            more_ports.dedup();
            let key = RowKey {
                port: first.port,
                owner: Owner::Exact(pid),
                uid,
                cgroup: None,
            };
            let addresses = addresses(
                inner
                    .iter()
                    .copied()
                    .filter(|listener| listener.port == first.port),
            );
            let mut row = self.row(key, addresses, process, subject, first.cgroup, by_pid);
            row.session = true;
            row.more_ports = more_ports;
            row.urls = urls_for(own);
            rows.push(row);
        }

        let mut groups: BTreeMap<RowKey, Vec<&Listener>> = BTreeMap::new();
        for listener in listeners {
            if listener
                .pid
                .is_some_and(|pid| pid == self.own_pid || consumed.contains(&pid))
            {
                continue;
            }
            let owner = match listener.pid {
                Some(pid) => Owner::Exact(pid),
                None => listener
                    .cgroup
                    .zip(listener.uid)
                    .and_then(|key| inferred.get(&key))
                    .map_or(Owner::Unknown, |pid| Owner::Inferred(*pid)),
            };
            let key = RowKey {
                port: listener.port,
                owner,
                uid: listener.uid,
                cgroup: (owner == Owner::Unknown)
                    .then_some(listener.cgroup)
                    .flatten(),
            };
            groups.entry(key).or_default().push(listener);
        }
        for (key, sockets) in groups {
            let process = key.owner.pid().and_then(|pid| by_pid.get(&pid).copied());
            let cgroup = sockets.iter().find_map(|listener| listener.cgroup);
            let mut row = self.row(
                key,
                addresses(sockets.iter().copied()),
                process,
                process,
                cgroup,
                by_pid,
            );
            row.urls = urls_for(&sockets);
            // NixOS wraps binaries, so the kernel name can be `.tailscaled-wra`.
            let tailscaled = row.subject_name == "tailscaled"
                || program_name(&row.subject_command) == "tailscaled";
            row.frontend = tailscaled
                && self.frontends.contains(&row.port())
                && row.addresses.iter().any(|ip| !ip.is_loopback());
            rows.push(row);
        }
        rows.sort_by(|a, b| a.key.cmp(&b.key));
        rows
    }

    fn row(
        &self,
        key: RowKey,
        addresses: Vec<IpAddr>,
        process: Option<&ProcessInfo>,
        subject: Option<&ProcessInfo>,
        cgroup: Option<u64>,
        by_pid: &HashMap<u32, &ProcessInfo>,
    ) -> Row {
        let cgroup_path = cgroup.and_then(|id| self.cgroups.get(&id)).cloned();
        let from_cgroup = cgroup_path.as_deref().and_then(Engine::of_cgroup);
        let engine = subject
            .and_then(|subject| engine_of(subject, by_pid))
            .or(from_cgroup.map(|(engine, _)| (engine, false)));
        let user = match key.uid {
            Some(uid) => self
                .users
                .get(&uid)
                .cloned()
                .unwrap_or_else(|| uid.to_string()),
            None => "?".to_string(),
        };
        Row {
            mine: key.uid.is_some() && key.uid == self.own_uid,
            group: match key.owner {
                Owner::Exact(pid) => process.is_some_and(|process| process.pgid == pid),
                Owner::Inferred(_) | Owner::Unknown => false,
            },
            key,
            more_ports: Vec::new(),
            addresses,
            user,
            session: false,
            program: process.map(program_of).unwrap_or_default(),
            command: process.map(command_of).unwrap_or_default(),
            subject_name: subject
                .map(|subject| sanitize(&subject.name))
                .unwrap_or_default(),
            subject_command: subject.map(command_of).unwrap_or_default(),
            dir: String::new(),
            container_id: from_cgroup.map(|(_, id)| id.to_string()),
            cgroup_path,
            engine,
            container: None,
            urls: Vec::new(),
            frontend: false,
            why: Vec::new(),
        }
    }

    /// Container names come from the engine's API, asked again only when
    /// the set of container ports changed or the last attempt failed.
    fn load_containers(&mut self, rows: &[Row]) {
        let wanted: BTreeSet<(Engine, u16)> = rows
            .iter()
            .filter_map(|row| row.engine.map(|(engine, _)| (engine, row.port())))
            .collect();
        if wanted == self.containers_key && self.container_note.is_none() {
            return;
        }
        let engines: BTreeSet<Engine> = wanted.iter().map(|(engine, _)| *engine).collect();
        self.containers_key = wanted;
        self.containers.clear();
        self.container_note = None;
        for engine in engines {
            match containers::list(engine) {
                Ok(found) => self.containers.extend(found),
                Err(error) => {
                    self.container_note = Some(format!("{} API: {error}", engine.name()));
                }
            }
        }
    }

    fn say(&mut self, tone: Tone, text: impl Into<String>) {
        self.message = Some((tone, text.into()));
    }

    fn handle(&mut self, key: Key, page: usize) -> Action {
        if let Some((pid, pending)) = self.pending.take() {
            if key != Key::Yes {
                self.say(Tone::Info, "Cancelled.");
                return Action::None;
            }
            let Some(row) = self
                .rows
                .iter()
                .find(|row| row.key.owner == Owner::Exact(pid))
                .cloned()
            else {
                self.say(Tone::Info, format!("pid {pid} already exited."));
                return Action::Refresh;
            };
            let (tone, text) = stop(&row, pid, pending);
            self.say(tone, text);
            self.stopped.insert(pid);
            return Action::RefreshSoon;
        }
        let last = self.visible.len().saturating_sub(1);
        match key {
            Key::Up => self.selected = self.selected.saturating_sub(1),
            Key::Down => self.selected = (self.selected + 1).min(last),
            Key::PageUp => self.selected = self.selected.saturating_sub(page),
            Key::PageDown => self.selected = (self.selected + page).min(last),
            Key::Home => self.selected = 0,
            Key::End => self.selected = last,
            Key::Refresh => {
                self.message = None;
                return Action::Refresh;
            }
            Key::Mine => {
                self.only_mine = !self.only_mine;
                let key = self.selected_row().map(|row| row.key.clone());
                self.filter(key);
                self.message = None;
            }
            Key::Quit | Key::Escape => return Action::Quit,
            Key::Stop => self.ask_stop(),
            Key::Yes | Key::Other => {}
        }
        Action::None
    }

    fn ask_stop(&mut self) {
        let Some(row) = self.selected_row() else {
            return;
        };
        let pid = match row.stop_target(self.own_pid) {
            Ok(pid) => pid,
            Err(reason) => {
                self.say(Tone::Warn, reason);
                return;
            }
        };
        // A Porthmeus session escalates to SIGKILL for its own children and
        // removes its Serve route; killing it outright would orphan both.
        let kind = if self.stopped.contains(&pid) && !row.session {
            Pending::Kill
        } else {
            Pending::Stop
        };
        let verb = match kind {
            Pending::Stop => "Stop",
            Pending::Kill => "Force-kill",
        };
        let name = if row.program.is_empty() {
            "process"
        } else {
            row.program.as_str()
        };
        let restart = match row.unit() {
            Some(unit) => format!(" {} may restart it.", unit.name),
            None => String::new(),
        };
        let text = format!(
            "{verb} {name} (pid {pid}) on :{}?{restart} y confirms, any other key cancels.",
            row.port()
        );
        self.say(Tone::Warn, text);
        self.pending = Some((pid, kind));
    }
}

fn stop(row: &Row, pid: u32, pending: Pending) -> (Tone, String) {
    let (signal, name) = match pending {
        Pending::Stop => (libc::SIGTERM, "SIGTERM"),
        Pending::Kill => (libc::SIGKILL, "SIGKILL"),
    };
    let own_group = u32::try_from(unsafe { libc::getpgrp() }).ok();
    let group = row.group && Some(pid) != own_group;
    let sent = if group {
        crate::signal::signal_process_group(pid, signal)
    } else {
        crate::signal::signal_pid(pid, signal)
    };
    if !sent {
        return (
            Tone::Bad,
            format!(
                "Could not signal pid {pid}: {}",
                std::io::Error::last_os_error()
            ),
        );
    }
    let target = if group { "process group" } else { "pid" };
    let text = match pending {
        Pending::Stop if !row.session => {
            format!("Sent {name} to {target} {pid}. x again force-kills.")
        }
        _ => format!("Sent {name} to {target} {pid}."),
    };
    (Tone::Good, text)
}

/// Collects `ports` from a Serve config and its foreground sessions.
fn frontend_ports(config: &tailscale::ServeConfig, ports: &mut Vec<u16>) {
    ports.extend(
        config
            .tcp
            .keys()
            .filter_map(|port| port.parse::<u16>().ok()),
    );
    for child in config.foreground.values().flatten() {
        frontend_ports(child, ports);
    }
}

/// Fills a row's explanations once container names are known.
fn describe(row: &mut Row, containers: &[Container]) {
    let found = row.engine.map(|(engine, forwarder)| {
        let (container, inside) = if forwarder {
            containers::published(containers, row.port(), &row.addresses)
                .map_or((None, None), |(container, port)| {
                    (Some(container), Some(port))
                })
        } else {
            let container = row
                .container_id
                .as_deref()
                .and_then(|id| containers::by_id(containers, engine, id));
            (container, None)
        };
        (engine, forwarder, container, inside)
    });
    row.container = found
        .and_then(|(_, _, container, _)| container)
        .map(|container| sanitize(&container.name));
    let why = {
        let facts = Facts {
            port: row.port(),
            session: row.session,
            served: !row.urls.is_empty(),
            serve_frontend: row.frontend,
            container: found.map(|(engine, forwarder, container, inside)| ContainerFact {
                engine,
                forwarder,
                name: row.container.as_deref(),
                image: container.map(|container| container.image.as_str()),
                container_port: inside,
            }),
            unit: row.unit(),
            name: &row.subject_name,
            command: &row.subject_command,
        };
        explain::explain(&facts)
    };
    row.why = why
        .into_iter()
        .map(|mut explanation| {
            explanation.text = sanitize(&explanation.text);
            explanation.detail = explanation.detail.map(|detail| sanitize(&detail));
            explanation
        })
        .collect();
}

/// The systemd unit a cgroup path names, skipping the user manager itself
/// and desktop launchers' `app-*` units, which say nothing about a port.
fn unit_of(path: &str) -> Option<UnitFact<'_>> {
    let last = path.rsplit('/').next()?;
    let unit = last.ends_with(".service") || last.ends_with(".socket");
    if !unit || last.starts_with("user@") || last.starts_with("app-") {
        return None;
    }
    Some(UnitFact {
        name: last,
        user: path.contains("/user@"),
    })
}

/// The cgroup's main process owned by `uid`: the one whose parent is outside
/// the cgroup (lowest pid on ties). A socket unit with no processes is held
/// by systemd itself.
fn infer_owner(path: &str, uid: u32, by_pid: &HashMap<u32, &ProcessInfo>) -> Option<u32> {
    if path == "/" {
        return None;
    }
    let members: Vec<u32> = discovery::cgroup_members(path)
        .into_iter()
        .filter(|pid| discovery::process_uid(*pid) == Some(uid))
        .collect();
    if members.is_empty() && uid == 0 && path.ends_with(".socket") {
        return Some(1);
    }
    members
        .iter()
        .copied()
        .filter(|pid| {
            by_pid
                .get(pid)
                .map_or(true, |process| !members.contains(&process.ppid))
        })
        .min()
}

/// A container engine behind `process`: a port forwarder by its own name,
/// or a process whose ancestry includes a container shim.
fn engine_of(process: &ProcessInfo, by_pid: &HashMap<u32, &ProcessInfo>) -> Option<(Engine, bool)> {
    // The kernel name, or argv[0] where a wrapper renamed the process.
    let named = |process: &ProcessInfo, test: fn(&str) -> Option<Engine>| {
        test(&process.name).or_else(|| test(program_name(&process.command)))
    };
    if let Some(engine) = named(process, Engine::of_forwarder) {
        return Some((engine, true));
    }
    let mut current = process.ppid;
    for _ in 0..MAX_ANCESTRY {
        let parent = by_pid.get(&current)?;
        if let Some(engine) = named(parent, Engine::of_ancestor) {
            return Some((engine, false));
        }
        if parent.ppid == current || parent.ppid == 0 {
            return None;
        }
        current = parent.ppid;
    }
    None
}

fn descendants(root: u32, children: &HashMap<u32, Vec<u32>>) -> Vec<u32> {
    let mut found = Vec::new();
    let mut seen: BTreeSet<u32> = BTreeSet::from([root]);
    let mut frontier = vec![root];
    while let Some(pid) = frontier.pop() {
        for child in children.get(&pid).into_iter().flatten() {
            if seen.insert(*child) {
                found.push(*child);
                frontier.push(*child);
            }
        }
    }
    found
}

/// Sorted, distinct bind addresses.
fn addresses<'a>(listeners: impl Iterator<Item = &'a Listener>) -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = listeners.map(|listener| canonical(listener.ip)).collect();
    found.sort();
    found.dedup();
    found
}

/// IPv4-mapped IPv6 addresses read as the IPv4 address they carry.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// A loopback client can reach this bind address.
fn reachable_locally(ip: IpAddr) -> bool {
    let ip = canonical(ip);
    ip.is_loopback() || ip.is_unspecified()
}

/// The program's file name from a command line: store and install paths
/// carry no signal in a narrow terminal. Retitled processes (`sshd: ...`)
/// lose the colon.
fn program_name(command: &str) -> &str {
    let program = command.split_whitespace().next().unwrap_or_default();
    let program = program.rsplit('/').next().unwrap_or(program);
    program.strip_suffix(':').unwrap_or(program)
}

fn program_of(process: &ProcessInfo) -> String {
    let program = program_name(&process.command);
    if program.is_empty() {
        sanitize(&process.name)
    } else {
        sanitize(program)
    }
}

/// The command line, or the kernel name for processes without one.
fn command_of(process: &ProcessInfo) -> String {
    if process.command.is_empty() {
        sanitize(&format!("[{}]", process.name))
    } else {
        sanitize(&process.command)
    }
}

fn home_relative(path: &str, home: &str) -> String {
    if home.len() > 1 {
        if path == home {
            return "~".to_string();
        }
        if let Some(rest) = path.strip_prefix(home).filter(|rest| rest.starts_with('/')) {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_string())
        .or_else(|_| std::env::var("HOSTNAME"))
        .map(|name| sanitize(&name))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_from_cgroup_paths() {
        let unit = |path| unit_of(path).map(|unit| (unit.name, unit.user));
        assert_eq!(
            unit("/system.slice/sshd.service"),
            Some(("sshd.service", false))
        );
        assert_eq!(
            unit("/user.slice/user-1000.slice/user@1000.service/app.slice/docker.service"),
            Some(("docker.service", true))
        );
        assert_eq!(
            unit("/system.slice/harmonia.socket"),
            Some(("harmonia.socket", false))
        );
        assert_eq!(unit("/user.slice/user-1000.slice/session-2.scope"), None);
        assert_eq!(unit("/user.slice/user-1000.slice/user@1000.service"), None);
        assert_eq!(
            unit("/user.slice/user-1000.slice/user@1000.service/app.slice/app-foot@1.service"),
            None
        );
    }

    #[test]
    fn parses_keys() {
        assert_eq!(
            keys(b"\x1b[Ajx\x1b[5~m"),
            [Key::Up, Key::Down, Key::Stop, Key::PageUp, Key::Mine]
        );
    }
}

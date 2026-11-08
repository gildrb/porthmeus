//! Drawing: the full-screen frame, and the plain table for pipes.

use super::explain::Source;
use super::{Owner, Row, State, Tone};
use crate::style::{Paint, Style};
use std::net::IpAddr;

const GAP: usize = 2;
/// Selection marker column.
const MARK: usize = 2;
const PORT: usize = 5;
/// Title, blank line, column header.
const TOP: usize = 3;
/// Message line and key hints.
const BOTTOM: usize = 2;
const LABEL: usize = 7;

/// Rows a page key moves by.
pub fn page_size(height: usize) -> usize {
    rows_area(height).max(1)
}

/// Detail lines for the selected row that fit: all six, a summary, or none.
fn detail_lines(height: usize) -> usize {
    if height >= 22 {
        6
    } else if height >= 15 {
        3
    } else {
        0
    }
}

fn rows_area(height: usize) -> usize {
    let detail = match detail_lines(height) {
        0 => 0,
        lines => lines + 1,
    };
    height.saturating_sub(TOP + BOTTOM + detail).max(1)
}

/// Widths of the optional and flexible columns; 0 hides a column.
#[derive(Clone, Copy, Debug)]
struct Widths {
    address: usize,
    process: usize,
    pid: usize,
    user: usize,
    what: usize,
    url: usize,
}

fn widths<'a>(rows: impl Iterator<Item = &'a Row> + Clone, width: usize) -> Widths {
    let natural = |measure: &dyn Fn(&Row) -> usize, header: usize, cap: usize| {
        rows.clone()
            .map(measure)
            .max()
            .unwrap_or(0)
            .max(header)
            .min(cap)
    };
    let address = natural(
        &|row| address_summary(&row.addresses).chars().count(),
        7,
        24,
    );
    let process = natural(&|row| process_text(row).chars().count(), 7, 16);
    let pid = natural(&|row| pid_text(row).chars().count(), 3, 7);
    let user = natural(&|row| row.user.chars().count(), 4, 14);
    let what = natural(&|row| what_text(row).chars().count(), 4, 44);
    let has_urls = rows.clone().any(|row| !row.urls.is_empty());
    let url = if has_urls {
        natural(&|row| url_text(row).chars().count(), 3, 60)
    } else {
        0
    };
    // Port, process, and what always show; the rest join while they fit.
    let what_floor = what.min(24);
    let fixed = MARK + PORT + GAP + process + GAP;
    let mut used = fixed + what_floor;
    let mut chosen = Widths {
        address: 0,
        process,
        pid: 0,
        user: 0,
        what: what_floor,
        url: 0,
    };
    for (slot, size) in [(0, pid), (1, user), (2, address)] {
        if used + size + GAP <= width {
            used += size + GAP;
            match slot {
                0 => chosen.pid = size,
                1 => chosen.user = size,
                _ => chosen.address = size,
            }
        }
    }
    let grow = (what - what_floor).min(width.saturating_sub(used));
    chosen.what += grow;
    used += grow;
    if url > 0 && used + GAP + 16 <= width {
        chosen.url = url.min(width - used - GAP);
    }
    if used > width {
        // Too narrow for even the floor: the explanation takes what is left.
        chosen.what = width.saturating_sub(fixed);
    }
    chosen
}

pub fn render(state: &mut State, width: usize, height: usize, style: Style) -> String {
    let area = rows_area(height);
    let detail = detail_lines(height);
    if state.selected < state.offset {
        state.offset = state.selected;
    } else if state.selected >= state.offset + area {
        state.offset = state.selected + 1 - area;
    }
    state.offset = state.offset.min(state.visible.len().saturating_sub(area));
    let state = &*state;
    let shown = state
        .visible
        .iter()
        .filter_map(|index| state.rows.get(*index));
    let columns = widths(shown.clone(), width);

    let mut frame = String::with_capacity(width * height * 2);
    frame.push_str("\x1b[H");
    title(&mut frame, state, width, style);
    end_line(&mut frame);
    end_line(&mut frame);
    header(&mut frame, &columns, width, style);
    end_line(&mut frame);

    let mut drawn = 0;
    if let Some(note) = empty_note(state) {
        let (paint, text) = note;
        frame.push_str("  ");
        style.push(&mut frame, paint, &fit(&text, width.saturating_sub(2)));
        end_line(&mut frame);
        drawn += 1;
    }
    for (position, row) in shown.enumerate().skip(state.offset).take(area) {
        row_line(
            &mut frame,
            row,
            &columns,
            width,
            position == state.selected,
            style,
        );
        end_line(&mut frame);
        drawn += 1;
    }
    for _ in drawn..area {
        end_line(&mut frame);
    }
    if detail > 0 {
        style.push(&mut frame, Paint::Dim, &"─".repeat(width));
        end_line(&mut frame);
        details(&mut frame, state, detail, width, style);
    }
    message(&mut frame, state, width, style);
    end_line(&mut frame);
    footer(&mut frame, state, width, style);
    frame.push_str("\x1b[0K\x1b[J");
    frame
}

fn end_line(frame: &mut String) {
    frame.push_str("\x1b[0K\r\n");
}

fn title(frame: &mut String, state: &State, width: usize, style: Style) {
    let total = state.rows.len();
    let mine = state.rows.iter().filter(|row| row.mine).count();
    let served = state.rows.iter().filter(|row| !row.urls.is_empty()).count();
    let mut left = format!(
        "{total} listening port{}  {mine} yours",
        if total == 1 { "" } else { "s" }
    );
    if served > 0 {
        left.push_str(&format!("  {served} on the tailnet"));
    }
    let filter = if state.only_mine {
        "  showing yours"
    } else {
        ""
    };
    let name = "porthmeus";
    let room = width.saturating_sub(name.len() + 2);
    let left = fit(&left, room);
    let left_len = left.chars().count();
    style.push(frame, Paint::Bold, &style.paint(Paint::Accent, name));
    frame.push_str("  ");
    frame.push_str(&left);
    let filter = fit(filter, room.saturating_sub(left_len));
    style.push(frame, Paint::Warn, &filter);
    let used = name.len() + 2 + left_len + filter.chars().count();
    let host = state.host.as_str();
    if !host.is_empty() && used + GAP + host.chars().count() <= width {
        frame.push_str(&" ".repeat(width - used - host.chars().count()));
        style.push(frame, Paint::Dim, host);
    }
}

fn header(frame: &mut String, columns: &Widths, width: usize, style: Style) {
    let mut line = " ".repeat(MARK);
    line.push_str(&format!("{:>PORT$}", "PORT"));
    let mut cell = |text: &str, size: usize, right: bool| {
        if size > 0 {
            line.push_str(&" ".repeat(GAP));
            line.push_str(&pad(text, size, right));
        }
    };
    cell("ADDRESS", columns.address, false);
    cell("PROCESS", columns.process, false);
    cell("PID", columns.pid, true);
    cell("USER", columns.user, false);
    cell("WHAT", columns.what, false);
    cell("URL", columns.url, false);
    style.push(frame, Paint::Dim, fit(&line, width).trim_end());
}

fn empty_note(state: &State) -> Option<(Paint, String)> {
    if !state.visible.is_empty() {
        return None;
    }
    Some(match (&state.scan_error, state.scanned_at) {
        (Some(error), _) => (Paint::Bad, format!("Can't list listening ports: {error}")),
        (None, None) => (Paint::Dim, "Scanning listening ports…".to_string()),
        (None, Some(_)) if state.only_mine && !state.rows.is_empty() => (
            Paint::Dim,
            format!(
                "None of the {} listening ports are yours. m shows all.",
                state.rows.len()
            ),
        ),
        (None, Some(_)) => (Paint::Dim, "No TCP port is listening.".to_string()),
    })
}

fn row_line(
    frame: &mut String,
    row: &Row,
    columns: &Widths,
    width: usize,
    selected: bool,
    style: Style,
) {
    // Your rows read at full weight; everyone else's are dimmed: read-only.
    let quiet = !row.mine;
    let normal = if quiet { Some(Paint::Dim) } else { None };
    let mut cells: Vec<(String, Option<Paint>)> = Vec::with_capacity(8);
    let mark = if selected { "› " } else { "  " };
    cells.push((
        format!("{mark}{:>PORT$}", row.port()),
        Some(if quiet { Paint::Dim } else { Paint::Bold }),
    ));
    let mut cell = |text: String, size: usize, right: bool, paint: Option<Paint>| {
        if size > 0 {
            let text = pad(&fit(&text, size), size, right);
            cells.push((format!("{:GAP$}{text}", ""), paint));
        }
    };
    cell(
        address_summary(&row.addresses),
        columns.address,
        false,
        Some(Paint::Dim),
    );
    cell(process_text(row), columns.process, false, normal);
    cell(pid_text(row), columns.pid, true, Some(Paint::Dim));
    cell(row.user.clone(), columns.user, false, normal);
    let what_paint = match row.why.first().map(|found| found.source) {
        Some(Source::Session | Source::Serve | Source::Frontend) => Some(Paint::Accent),
        _ => normal,
    };
    cell(what_text(row), columns.what, false, what_paint);
    cell(url_text(row), columns.url, false, Some(Paint::Accent));

    if selected {
        let plain: String = cells.iter().map(|(text, _)| text.as_str()).collect();
        style.push(
            frame,
            Paint::Reverse,
            &pad(&fit(&plain, width), width, false),
        );
        return;
    }
    // Each cell in its paint, cut at the screen edge.
    let mut room = width;
    for (text, paint) in &cells {
        if room == 0 {
            break;
        }
        let piece = fit(text, room);
        room = room.saturating_sub(piece.chars().count());
        match paint {
            Some(paint) => style.push(frame, *paint, &piece),
            None => frame.push_str(&piece),
        }
    }
}

fn details(frame: &mut String, state: &State, lines: usize, width: usize, style: Style) {
    let Some(row) = state.selected_row() else {
        for _ in 0..lines {
            end_line(frame);
        }
        return;
    };
    let room = width.saturating_sub(LABEL + 1);
    // Line 1: port and every address.
    let mut head = format!(":{}", row.port());
    for port in &row.more_ports {
        head.push_str(&format!(" :{port}"));
    }
    frame.push(' ');
    style.push(frame, Paint::Bold, &fit(&head, width.saturating_sub(1)));
    let addresses = row
        .addresses
        .iter()
        .map(address_text)
        .collect::<Vec<_>>()
        .join(", ");
    let used = 1 + head.chars().count();
    if used + 4 < width {
        style.push(frame, Paint::Dim, " on ");
        frame.push_str(&fit(&addresses, width - used - 4));
    }
    end_line(frame);

    let what = if row.why.is_empty() {
        None
    } else {
        Some(
            row.why
                .iter()
                .map(|found| match &found.detail {
                    Some(detail) => format!("{} ({detail})", found.text),
                    None => found.text.clone(),
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
    };
    labeled(
        frame,
        "what",
        what.as_deref(),
        "no rule matches this port",
        room,
        style,
    );
    end_line(frame);
    let owner = owner_text(row, state.own_pid);
    labeled(frame, "owner", Some(&owner), "", room, style);
    end_line(frame);
    if lines < 6 {
        return;
    }
    let urls = row.urls.join("  ");
    labeled(
        frame,
        "url",
        (!urls.is_empty()).then_some(urls.as_str()),
        "not on the tailnet",
        room,
        style,
    );
    end_line(frame);
    labeled(
        frame,
        "cmd",
        (!row.command.is_empty()).then_some(row.command.as_str()),
        "hidden without root",
        room,
        style,
    );
    end_line(frame);
    let unreadable = if row.mine {
        "unknown"
    } else {
        "readable only by its owner"
    };
    labeled(
        frame,
        "cwd",
        (!row.dir.is_empty()).then_some(row.dir.as_str()),
        unreadable,
        room,
        style,
    );
    end_line(frame);
}

fn labeled(
    frame: &mut String,
    label: &str,
    value: Option<&str>,
    missing: &str,
    room: usize,
    style: Style,
) {
    frame.push(' ');
    style.push(frame, Paint::Dim, &format!("{label:<LABEL$}"));
    match value {
        Some(value) => frame.push_str(&fit(value, room)),
        None => style.push(frame, Paint::Dim, &fit(missing, room)),
    }
}

fn owner_text(row: &Row, own_pid: u32) -> String {
    let name = if row.program.is_empty() {
        "process"
    } else {
        row.program.as_str()
    };
    let user = if row.mine {
        format!("{} (you)", row.user)
    } else {
        row.user.clone()
    };
    let status = match (row.stop_target(own_pid), row.engine) {
        (Ok(_), _) => "x stops it".to_string(),
        (Err(_), Some((engine, _))) if row.mine => format!("stop it with {}", engine.name()),
        (Err(_), _) => "read-only".to_string(),
    };
    match row.key.owner {
        Owner::Exact(pid) => format!("{name}, pid {pid}, user {user}; {status}"),
        Owner::Inferred(pid) => format!(
            "{name}, pid {pid}, user {user}; {status}; inferred from its cgroup, only root sees the exact holder"
        ),
        Owner::Unknown => format!("user {user}; {status}; only root sees which process holds it"),
    }
}

fn message(frame: &mut String, state: &State, width: usize, style: Style) {
    let room = width.saturating_sub(1);
    frame.push(' ');
    if let Some((tone, text)) = &state.message {
        let paint = match tone {
            Tone::Info => Paint::Dim,
            Tone::Good => Paint::Good,
            Tone::Warn => Paint::Warn,
            Tone::Bad => Paint::Bad,
        };
        style.push(frame, paint, &fit(text, room));
        return;
    }
    if let (Some(error), false) = (&state.scan_error, state.visible.is_empty()) {
        style.push(
            frame,
            Paint::Bad,
            &fit(&format!("Scan failed: {error}"), room),
        );
        return;
    }
    let note = match (&state.tailscale_note, &state.container_note) {
        (Some(note), _) => format!("Tailscale URLs unavailable: {note}"),
        (None, Some(note)) => format!("Container names unavailable: {note}"),
        (None, None) => return,
    };
    style.push(frame, Paint::Dim, &fit(&note, room));
}

fn footer(frame: &mut String, state: &State, width: usize, style: Style) {
    let filter = if state.only_mine {
        "all ports"
    } else {
        "yours"
    };
    let hints = [
        ("↑↓", "select"),
        ("x", "stop"),
        ("m", filter),
        ("r", "refresh"),
        ("q", "quit"),
    ];
    let mut used = 1;
    frame.push(' ');
    for (key, label) in hints {
        let size = key.chars().count() + 1 + label.len() + 3;
        if used + size > width {
            break;
        }
        used += size;
        style.push(frame, Paint::Bold, key);
        frame.push(' ');
        style.push(frame, Paint::Dim, label);
        frame.push_str("   ");
    }
}

/// The plain table for pipes: every row, no truncation, no escapes.
pub fn table(state: &State) -> String {
    let headers = ["PORT", "ADDRESS", "PID", "USER", "PROCESS", "WHAT", "URL"];
    let lines: Vec<[String; 7]> = state
        .rows
        .iter()
        .map(|row| {
            [
                row.port().to_string(),
                row.addresses
                    .iter()
                    .map(address_text)
                    .collect::<Vec<_>>()
                    .join(","),
                pid_text(row),
                row.user.clone(),
                process_text(row),
                what_text(row),
                row.urls.join(" "),
            ]
        })
        .collect();
    let mut sizes = headers.map(str::len);
    for line in &lines {
        for (size, cell) in sizes.iter_mut().zip(line) {
            *size = (*size).max(cell.chars().count());
        }
    }
    let mut text = String::new();
    let mut emit = |cells: [&str; 7]| {
        let mut line = String::new();
        for (index, (cell, size)) in cells.iter().zip(sizes).enumerate() {
            if index > 0 {
                line.push_str("  ");
            }
            line.push_str(&pad(cell, size, false));
        }
        text.push_str(line.trim_end());
        text.push('\n');
    };
    emit(headers);
    for line in &lines {
        emit([
            &line[0], &line[1], &line[2], &line[3], &line[4], &line[5], &line[6],
        ]);
    }
    text
}

/// Every bind address in one cell: `*` for all interfaces, `localhost` for
/// loopback only, else the first address and a count.
fn address_summary(addresses: &[IpAddr]) -> String {
    match addresses {
        [] => "?".to_string(),
        _ if addresses.iter().all(IpAddr::is_unspecified) => "*".to_string(),
        _ if addresses.iter().all(IpAddr::is_loopback) => "localhost".to_string(),
        [only] => address_text(only),
        [first, rest @ ..] => format!("{} +{}", address_text(first), rest.len()),
    }
}

fn address_text(ip: &IpAddr) -> String {
    if ip.is_unspecified() {
        match ip {
            IpAddr::V4(_) => "0.0.0.0".to_string(),
            IpAddr::V6(_) => "[::]".to_string(),
        }
    } else {
        ip.to_string()
    }
}

fn process_text(row: &Row) -> String {
    if row.program.is_empty() {
        "?".to_string()
    } else {
        row.program.clone()
    }
}

fn pid_text(row: &Row) -> String {
    match row.key.owner {
        Owner::Exact(pid) | Owner::Inferred(pid) => pid.to_string(),
        Owner::Unknown => "-".to_string(),
    }
}

/// The leading explanation; a session or Serve route also names what it
/// serves.
fn what_text(row: &Row) -> String {
    let mut found = row.why.iter();
    let Some(first) = found.next() else {
        return String::new();
    };
    let prefix = match first.source {
        Source::Session => "porthmeus",
        Source::Serve => "Serve",
        Source::Frontend | Source::Container | Source::Unit | Source::Program | Source::Port => {
            return first.text.clone()
        }
    };
    match found.next() {
        Some(next) => format!("{prefix}: {}", next.text),
        None => first.text.clone(),
    }
}

fn url_text(row: &Row) -> String {
    match row.urls.as_slice() {
        [] => String::new(),
        [only] => only.clone(),
        [first, rest @ ..] => format!("{first} +{}", rest.len()),
    }
}

/// Truncates to `width` characters, marking the cut with an ellipsis.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut cut: String = text.chars().take(width - 1).collect();
    cut.push('…');
    cut
}

fn pad(text: &str, width: usize, right: bool) -> String {
    let count = text.chars().count();
    if count >= width {
        return text.to_string();
    }
    let fill = " ".repeat(width - count);
    if right {
        fill + text
    } else {
        format!("{text}{fill}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_addresses() {
        let parse = |text: &str| text.parse::<IpAddr>().ok();
        let list = |items: &[&str]| {
            items
                .iter()
                .filter_map(|item| parse(item))
                .collect::<Vec<_>>()
        };
        assert_eq!(address_summary(&list(&["0.0.0.0", "::"])), "*");
        assert_eq!(address_summary(&list(&["127.0.0.1", "::1"])), "localhost");
        assert_eq!(
            address_summary(&list(&["100.64.0.1", "fd7a:115c:a1e0::1"])),
            "100.64.0.1 +1"
        );
    }

    #[test]
    fn fits_and_pads() {
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abc", 4), "abc");
        assert_eq!(pad("7", 3, true), "  7");
    }

    #[test]
    fn narrow_terminals_keep_port_process_and_what() {
        let columns = widths(std::iter::empty(), 40);
        assert_eq!(columns.address, 0);
        assert!(columns.what > 0 && columns.process > 0);
        let wide = widths(std::iter::empty(), 160);
        assert!(wide.address > 0 && wide.pid > 0 && wide.user > 0);
    }
}

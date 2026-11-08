//! Restrained terminal styling. Escape codes go only to terminals (never with
//! TERM=dumb); colors are also dropped under NO_COLOR, keeping bold, dim, and
//! reverse so hierarchy and selection survive.

use std::io::{IsTerminal, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paint {
    Bold,
    Dim,
    Reverse,
    /// Links and the product name.
    Accent,
    Good,
    Warn,
    Bad,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    ansi: bool,
    color: bool,
}

impl Style {
    pub const PLAIN: Self = Self {
        ansi: false,
        color: false,
    };

    pub fn stdout() -> Self {
        Self::detect(std::io::stdout().is_terminal())
    }

    pub fn stderr() -> Self {
        Self::detect(std::io::stderr().is_terminal())
    }

    /// For a terminal already known to be one (the dashboard's).
    pub fn terminal() -> Self {
        Self::detect(true)
    }

    fn detect(terminal: bool) -> Self {
        let dumb = std::env::var_os("TERM").is_some_and(|term| term == "dumb");
        let ansi = terminal && !dumb;
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        Self {
            ansi,
            color: ansi && !no_color,
        }
    }

    pub fn is_terminal(self) -> bool {
        self.ansi
    }

    /// The SGR sequence that starts `paint`, or "" when it is unavailable.
    pub fn open(self, paint: Paint) -> &'static str {
        match paint {
            Paint::Bold if self.ansi => "\x1b[1m",
            Paint::Dim if self.ansi => "\x1b[2m",
            Paint::Reverse if self.ansi => "\x1b[7m",
            Paint::Accent if self.color => "\x1b[36m",
            Paint::Good if self.color => "\x1b[32m",
            Paint::Warn if self.color => "\x1b[33m",
            Paint::Bad if self.color => "\x1b[31m",
            // Without color, errors and prompts still stand out.
            Paint::Bad | Paint::Warn if self.ansi => "\x1b[1m",
            _ => "",
        }
    }

    pub fn reset(self) -> &'static str {
        if self.ansi {
            "\x1b[0m"
        } else {
            ""
        }
    }

    /// Appends `text` in `paint` to `out`.
    pub fn push(self, out: &mut String, paint: Paint, text: &str) {
        let open = self.open(paint);
        out.push_str(open);
        out.push_str(text);
        if !open.is_empty() {
            out.push_str(self.reset());
        }
    }

    pub fn paint(self, paint: Paint, text: &str) -> String {
        let mut out = String::with_capacity(text.len() + 8);
        self.push(&mut out, paint, text);
        out
    }
}

/// `Error: message` on stderr, the label in red on a terminal.
pub fn print_error(message: &str) {
    let style = Style::stderr();
    let mut text = String::new();
    style.push(&mut text, Paint::Bad, "Error:");
    text.push(' ');
    text.push_str(message);
    text.push('\n');
    // Nothing useful remains to do when stderr itself fails.
    let _ = std::io::stderr().write_all(text.as_bytes());
}

/// Replaces control characters, so process-controlled text (command lines,
/// paths) cannot move the cursor or restyle the terminal.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_style_adds_nothing() {
        assert_eq!(Style::PLAIN.paint(Paint::Bad, "x"), "x");
        assert_eq!(Style::PLAIN.reset(), "");
    }

    #[test]
    fn sanitize_strips_escapes() {
        assert_eq!(sanitize("a\x1b[2Jb\n"), "a?[2Jb?");
    }
}

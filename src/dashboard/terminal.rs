//! Raw-mode alternate screen and window size.

/// Raw-mode alternate screen; restored on drop, including during panics.
pub struct Raw {
    original: libc::termios,
}

impl Raw {
    pub fn enter() -> Result<Self, String> {
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
            return Err(format!(
                "read terminal mode: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut raw = original;
        // Keep ISIG: Ctrl-C arrives as SIGINT and ends the loop cleanly.
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::IEXTEN);
        raw.c_iflag &= !(libc::IXON | libc::ICRNL);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(format!(
                "set terminal mode: {}",
                std::io::Error::last_os_error()
            ));
        }
        // Alternate screen, hidden cursor, no line wrap: a frame never scrolls.
        write_str("\x1b[?1049h\x1b[?25l\x1b[?7l");
        Ok(Self { original })
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        write_str("\x1b[?7h\x1b[?25h\x1b[?1049l");
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

fn write_str(text: &str) {
    use std::io::Write;
    let mut stdout = std::io::stdout();
    // Restoring the screen is best effort; a closed terminal needs nothing.
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
}

/// Columns and rows; 80x24 when the size cannot be read.
pub fn size() -> (usize, usize) {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    if ok && size.ws_col > 0 && size.ws_row > 0 {
        (usize::from(size.ws_col), usize::from(size.ws_row))
    } else {
        (80, 24)
    }
}

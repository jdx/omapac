//! Small terminal interactions shared by commands.

use std::io::{BufRead, IsTerminal, Write};

use eyre::{Result, bail};

/// Ask a yes/no question on stderr and read the answer from stdin.
///
/// `default` is what an empty answer means. Fails when stdin is not a
/// terminal, because a command that would block forever or silently take
/// the default is worse than one that asks for `-y`.
pub fn confirm(question: &str, default: bool) -> Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!("{question}: no terminal to ask on; pass -y to proceed without asking");
    }
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        eprint!("{question} {hint} ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            eprintln!();
            return Ok(false);
        }
        match line.trim().to_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("please answer y or n"),
        }
    }
}

/// Whether the process can ask questions.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

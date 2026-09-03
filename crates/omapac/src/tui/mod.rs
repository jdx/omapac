//! Terminal pickers and a pager on ratatui: what the Omarchy menu rows
//! call, and what `--pick` and `--pager` flags open. The widgets are
//! plain state machines fed key events, so they are tested through the
//! test backend without a terminal.

pub mod pager;
pub mod picker;

use std::io::IsTerminal;

use eyre::{Result, bail};
use ratatui::crossterm::event::{self, Event};

pub use pager::Pager;
pub use picker::{Item, Outcome, Picker};

/// Fail unless both stdin and stdout are terminals.
pub fn require_terminal(what: &str, alternative: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("{what} needs a terminal; {alternative}");
    }
    Ok(())
}

/// Open a picker; `None` when cancelled, else the chosen item indexes.
pub fn pick(title: &str, items: Vec<Item>, multi: bool) -> Result<Option<Vec<usize>>> {
    let mut picker = Picker::new(title, items, multi);
    let mut terminal = ratatui::init();
    let outcome = loop {
        if let Err(err) = terminal.draw(|frame| picker.render(frame)) {
            ratatui::restore();
            return Err(err.into());
        }
        let event = match event::read() {
            Ok(event) => event,
            Err(err) => {
                ratatui::restore();
                return Err(err.into());
            }
        };
        if let Event::Key(key) = event
            && let Some(outcome) = picker.handle(key)
        {
            break outcome;
        }
    };
    ratatui::restore();
    // Key repeat and double-press events from the picker must not answer the
    // transaction confirmation that follows it.
    while event::poll(std::time::Duration::ZERO)? {
        let _ = event::read()?;
    }
    Ok(match outcome {
        Outcome::Confirm(chosen) => Some(chosen),
        Outcome::Cancel => None,
    })
}

/// Show text in a scrollable pager until the user leaves.
pub fn page(title: &str, text: &str) -> Result<()> {
    let mut pager = Pager::new(title, text);
    let mut terminal = ratatui::init();
    loop {
        if let Err(err) = terminal.draw(|frame| pager.render(frame)) {
            ratatui::restore();
            return Err(err.into());
        }
        let event = match event::read() {
            Ok(event) => event,
            Err(err) => {
                ratatui::restore();
                return Err(err.into());
            }
        };
        if let Event::Key(key) = event
            && pager.handle(key)
        {
            break;
        }
    }
    ratatui::restore();
    Ok(())
}

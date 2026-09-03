//! A scrollable text view for reviews and diffs.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

#[derive(Debug)]
pub struct Pager {
    title: String,
    lines: Vec<String>,
    scroll: usize,
    /// Rows the last render had for text, for paging.
    height: usize,
}

impl Pager {
    pub fn new(title: &str, text: &str) -> Pager {
        Pager {
            title: title.to_string(),
            lines: text.lines().map(str::to_string).collect(),
            scroll: 0,
            height: 20,
        }
    }

    pub fn scroll(&self) -> usize {
        self.scroll
    }

    fn max_scroll(&self) -> usize {
        self.lines.len().saturating_sub(self.height)
    }

    /// Feed a key; `true` when the user leaves.
    pub fn handle(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => return true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = (self.scroll + 1).min(self.max_scroll())
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') | KeyCode::Char('f') => {
                self.scroll = (self.scroll + self.height).min(self.max_scroll())
            }
            KeyCode::PageUp | KeyCode::Char('b') => {
                self.scroll = self.scroll.saturating_sub(self.height)
            }
            KeyCode::Home | KeyCode::Char('g') => self.scroll = 0,
            KeyCode::End | KeyCode::Char('G') => self.scroll = self.max_scroll(),
            _ => {}
        }
        false
    }

    pub fn render(&mut self, frame: &mut Frame<'_>) {
        let [text_area, help_area] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(frame.area());
        self.height = text_area.height.saturating_sub(2) as usize;
        self.scroll = self.scroll.min(self.max_scroll());
        let lines: Vec<Line<'_>> = self
            .lines
            .iter()
            .skip(self.scroll)
            .take(self.height)
            .map(|line| {
                let trimmed = line.trim_start();
                let style = if line.starts_with('+') && !line.starts_with("+++") {
                    Style::default().fg(Color::Green)
                } else if line.starts_with('-') && !line.starts_with("---") {
                    Style::default().fg(Color::Red)
                } else if line.starts_with("@@") || line.starts_with("==>") {
                    Style::default().fg(Color::Cyan)
                } else if trimmed.starts_with("DENY") || line.contains(" deny ") {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else if line.starts_with("WARN") || line.contains(" warn ") {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(line.clone(), style))
            })
            .collect();
        let title = format!(
            " {} ({}-{} of {}) ",
            self.title,
            (self.scroll + 1).min(self.lines.len()),
            (self.scroll + self.height).min(self.lines.len()),
            self.lines.len()
        );
        frame.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
            text_area,
        );
        frame.render_widget(
            Paragraph::new("j/k or arrows scroll  space/b page  g/G ends  q leaves")
                .style(Style::default().add_modifier(Modifier::DIM)),
            help_area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn scrolls_within_bounds_and_leaves() {
        let text: String = (1..=50).map(|i| format!("line {i}\n")).collect();
        let mut pager = Pager::new("Review yay", &text);
        let backend = TestBackend::new(40, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| pager.render(f)).unwrap();
        assert_eq!(pager.height, 9);
        assert!(!pager.handle(key(KeyCode::Char('j'))));
        assert_eq!(pager.scroll(), 1);
        pager.handle(key(KeyCode::Char(' ')));
        assert_eq!(pager.scroll(), 10);
        pager.handle(key(KeyCode::End));
        assert_eq!(pager.scroll(), 41);
        pager.handle(key(KeyCode::Down));
        assert_eq!(pager.scroll(), 41, "cannot scroll past the end");
        pager.handle(key(KeyCode::Char('g')));
        assert_eq!(pager.scroll(), 0);
        pager.handle(key(KeyCode::Up));
        assert_eq!(pager.scroll(), 0);
        terminal.draw(|f| pager.render(f)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let first: String = (0..40)
            .map(|x| buffer[(x, 0)].symbol().to_string())
            .collect();
        assert!(first.contains("Review yay (1-9 of 50)"), "{first}");
        assert!(pager.handle(key(KeyCode::Char('q'))));
        assert!(pager.handle(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    }
}

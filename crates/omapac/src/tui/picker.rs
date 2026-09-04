//! A filterable list with single or multiple selection.

use std::collections::BTreeSet;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The main column, such as a package name.
    pub label: String,
    /// The second column, such as a version and repository.
    pub detail: String,
    /// A trailing note, such as `installed` or a trust tier.
    pub note: String,
}

impl Item {
    pub fn new(
        label: impl Into<String>,
        detail: impl Into<String>,
        note: impl Into<String>,
    ) -> Item {
        Item {
            label: label.into(),
            detail: detail.into(),
            note: note.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Confirm(Vec<usize>),
    Cancel,
}

#[derive(Debug)]
pub struct Picker {
    title: String,
    items: Vec<Item>,
    filter: String,
    /// Position within the visible (filtered) list.
    cursor: usize,
    list_state: ListState,
    selected: BTreeSet<usize>,
    multi: bool,
}

impl Picker {
    pub fn new(title: &str, items: Vec<Item>, multi: bool) -> Picker {
        Picker {
            title: title.to_string(),
            items,
            filter: String::new(),
            cursor: 0,
            list_state: ListState::default(),
            selected: BTreeSet::new(),
            multi,
        }
    }

    /// Indexes of items matching the filter, in order.
    pub fn visible(&self) -> Vec<usize> {
        let needle = self.filter.to_lowercase();
        self.items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                needle.is_empty()
                    || item.label.to_lowercase().contains(&needle)
                    || item.detail.to_lowercase().contains(&needle)
            })
            .map(|(i, _)| i)
            .collect()
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn selected(&self) -> Vec<usize> {
        self.selected.iter().copied().collect()
    }

    /// Feed a key; `Some` when the picker is done.
    pub fn handle(&mut self, key: KeyEvent) -> Option<Outcome> {
        let visible = self.visible();
        match key.code {
            KeyCode::Esc => return Some(Outcome::Cancel),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Some(Outcome::Cancel);
            }
            KeyCode::Enter => {
                if self.multi && !self.selected.is_empty() {
                    return Some(Outcome::Confirm(self.selected()));
                }
                return match visible.get(self.cursor) {
                    Some(&index) => Some(Outcome::Confirm(vec![index])),
                    None => Some(Outcome::Cancel),
                };
            }
            KeyCode::Down => self.cursor = (self.cursor + 1).min(visible.len().saturating_sub(1)),
            KeyCode::Up => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::PageDown => {
                self.cursor = (self.cursor + 10).min(visible.len().saturating_sub(1))
            }
            KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(10),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = visible.len().saturating_sub(1),
            KeyCode::Tab | KeyCode::Char(' ') if self.multi => {
                if let Some(&index) = visible.get(self.cursor) {
                    if !self.selected.remove(&index) {
                        self.selected.insert(index);
                    }
                    self.cursor = (self.cursor + 1).min(visible.len().saturating_sub(1));
                }
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.cursor = 0;
                *self.list_state.offset_mut() = 0;
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.filter.push(c);
                self.cursor = 0;
                *self.list_state.offset_mut() = 0;
            }
            _ => {}
        }
        None
    }

    pub fn render(&mut self, frame: &mut Frame<'_>) {
        let [list_area, filter_area, help_area] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        let visible = self.visible();
        let width = visible
            .iter()
            .map(|&i| self.items[i].label.len())
            .max()
            .unwrap_or(0);
        let rows: Vec<ListItem<'_>> = visible
            .iter()
            .map(|&i| {
                let item = &self.items[i];
                let mark = if !self.multi {
                    "  "
                } else if self.selected.contains(&i) {
                    "* "
                } else {
                    "  "
                };
                let mut spans = vec![
                    Span::raw(mark),
                    Span::styled(
                        format!("{:width$}  ", item.label, width = width),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(item.detail.clone()),
                ];
                if !item.note.is_empty() {
                    spans.push(Span::styled(
                        format!("  [{}]", item.note),
                        Style::default().add_modifier(Modifier::DIM),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();
        let count = if self.multi {
            format!(
                " {} ({} shown, {} selected) ",
                self.title,
                visible.len(),
                self.selected.len()
            )
        } else {
            format!(" {} ({} shown) ", self.title, visible.len())
        };
        let list = List::new(rows)
            .block(Block::default().borders(Borders::ALL).title(count))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        if !visible.is_empty() {
            self.list_state
                .select(Some(self.cursor.min(visible.len() - 1)));
        } else {
            self.list_state.select(None);
        }
        frame.render_stateful_widget(list, list_area, &mut self.list_state);
        frame.render_widget(
            Paragraph::new(self.filter.as_str())
                .block(Block::default().borders(Borders::ALL).title(" filter ")),
            filter_area,
        );
        let help = if self.multi {
            "type to filter  up/down move  space select  enter confirm  esc cancel"
        } else {
            "type to filter  up/down move  enter choose  esc cancel"
        };
        frame.render_widget(
            Paragraph::new(help).style(Style::default().add_modifier(Modifier::DIM)),
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

    fn items() -> Vec<Item> {
        vec![
            Item::new("helix", "25.07-1 extra", "arch"),
            Item::new("hyprland", "0.51-1 omarchy", "opr, installed"),
            Item::new("yay", "13.0.1-1 omarchy", "opr"),
        ]
    }

    fn screen(picker: &mut Picker) -> String {
        let backend = TestBackend::new(70, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| picker.render(f)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            let line: String = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    #[test]
    fn filters_selects_and_confirms() {
        let mut p = Picker::new("Install", items(), true);
        assert_eq!(p.visible(), vec![0, 1, 2]);
        // "hy" would also match "omarchy" in a detail column.
        for c in "hy".chars() {
            assert!(p.handle(key(KeyCode::Char(c))).is_none());
        }
        assert_eq!(p.visible(), vec![1, 2]);
        p.handle(key(KeyCode::Char('p')));
        assert_eq!(p.visible(), vec![1]);
        assert!(p.handle(key(KeyCode::Char(' '))).is_none());
        assert_eq!(p.selected(), vec![1]);
        for _ in 0..3 {
            p.handle(key(KeyCode::Backspace));
        }
        assert_eq!(p.visible(), vec![0, 1, 2]);
        p.handle(key(KeyCode::End));
        p.handle(key(KeyCode::Tab));
        assert_eq!(p.selected(), vec![1, 2]);
        // Toggling off again: the cursor stayed on the last row.
        p.handle(key(KeyCode::Up));
        p.handle(key(KeyCode::Char(' ')));
        assert_eq!(p.selected(), vec![2]);
        let text = screen(&mut p);
        assert!(text.contains("Install (3 shown, 1 selected)"), "{text}");
        assert!(text.contains("* yay"), "{text}");
        assert!(text.contains("[opr, installed]"), "{text}");
        assert!(text.contains("space select"), "{text}");
        assert_eq!(
            p.handle(key(KeyCode::Enter)),
            Some(Outcome::Confirm(vec![2]))
        );
    }

    #[test]
    fn single_choice_and_cancel() {
        let mut p = Picker::new("Remove", items(), false);
        p.handle(key(KeyCode::Down));
        assert_eq!(
            p.handle(key(KeyCode::Enter)),
            Some(Outcome::Confirm(vec![1]))
        );
        let mut p = Picker::new("Remove", items(), false);
        // Space is a filter character when not multi-selecting.
        p.handle(key(KeyCode::Char('z')));
        assert!(p.visible().is_empty());
        assert_eq!(p.handle(key(KeyCode::Enter)), Some(Outcome::Cancel));
        assert_eq!(p.handle(key(KeyCode::Esc)), Some(Outcome::Cancel));
        assert_eq!(
            p.handle(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Outcome::Cancel)
        );
        let text = screen(&mut p);
        assert!(text.contains("Remove (0 shown)"), "{text}");
        assert!(text.contains("enter choose"), "{text}");
    }

    #[test]
    fn scrolling_state_survives_each_render() {
        let items = (0..12)
            .map(|index| Item::new(format!("item-{index:02}"), "", ""))
            .collect();
        let mut picker = Picker::new("Long", items, false);
        picker.handle(key(KeyCode::End));
        screen(&mut picker);
        let bottom_offset = picker.list_state.offset();
        assert!(bottom_offset > 0);

        picker.handle(key(KeyCode::Up));
        screen(&mut picker);
        assert_eq!(picker.list_state.offset(), bottom_offset);
        assert_eq!(picker.list_state.selected(), Some(10));
    }
}

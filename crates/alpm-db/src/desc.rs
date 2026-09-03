//! The `%KEY%` block format shared by local `desc` and `files` entries and
//! by sync database `desc` entries.
//!
//! A block is a `%KEY%` line followed by value lines up to a blank line.
//! Keys may repeat in principle; libalpm reads them in order and the last
//! occurrence wins for scalar fields, which this parser reproduces by
//! keeping every block in order and letting callers ask for the last one.

use std::collections::BTreeMap;

/// Parsed `%KEY%` blocks, in file order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fields {
    blocks: Vec<(String, Vec<String>)>,
    index: BTreeMap<String, Vec<usize>>,
}

impl Fields {
    /// Parse a whole file.
    pub fn parse(text: &str) -> Fields {
        let mut fields = Fields::default();
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            let line = line.trim_end_matches('\r');
            let Some(key) = key_of(line) else {
                continue;
            };
            let mut values = Vec::new();
            for value in lines.by_ref() {
                let value = value.trim_end_matches('\r');
                if value.is_empty() {
                    break;
                }
                values.push(value.to_string());
            }
            fields.push(key, values);
        }
        fields
    }

    fn push(&mut self, key: &str, values: Vec<String>) {
        self.index
            .entry(key.to_string())
            .or_default()
            .push(self.blocks.len());
        self.blocks.push((key.to_string(), values));
    }

    /// The first value of the last block with this key.
    pub fn first(&self, key: &str) -> Option<&str> {
        self.all(key).first().map(String::as_str)
    }

    /// Every value of the last block with this key, or empty.
    pub fn all(&self, key: &str) -> &[String] {
        match self.index.get(key).and_then(|positions| positions.last()) {
            Some(&position) => &self.blocks[position].1,
            None => &[],
        }
    }

    /// The first value of the last block with this key, parsed as a number.
    pub fn number<T: std::str::FromStr>(&self, key: &str) -> Option<T> {
        self.first(key).and_then(|value| value.parse().ok())
    }

    /// Whether any block with this key exists.
    pub fn has(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// The blocks in file order.
    pub fn blocks(&self) -> &[(String, Vec<String>)] {
        &self.blocks
    }

    /// Absorb another file's blocks after this one's, as libalpm does when
    /// an older sync database splits `desc` and `depends`.
    pub fn extend(&mut self, other: Fields) {
        for (key, values) in other.blocks {
            self.push(&key, values);
        }
    }
}

fn key_of(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('%')?.strip_suffix('%')?;
    if inner.is_empty()
        || !inner
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    Some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_blocks_in_order() {
        let fields = Fields::parse("%NAME%\npacman\n\n%DEPENDS%\nbash\ncurl\n\n%SIZE%\n42\n");
        assert_eq!(fields.first("NAME"), Some("pacman"));
        assert_eq!(fields.all("DEPENDS"), ["bash", "curl"]);
        assert_eq!(fields.number::<u64>("SIZE"), Some(42));
        assert_eq!(fields.first("MISSING"), None);
        assert!(fields.all("MISSING").is_empty());
        assert_eq!(fields.blocks().len(), 3);
    }

    #[test]
    fn last_block_wins_and_empty_blocks_are_fine() {
        let fields = Fields::parse("%NAME%\nfirst\n\n%NAME%\nsecond\n\n%GROUPS%\n\n%URL%\n");
        assert_eq!(fields.first("NAME"), Some("second"));
        assert!(fields.has("GROUPS"));
        assert!(fields.all("GROUPS").is_empty());
        assert_eq!(fields.first("URL"), None);
    }

    #[test]
    fn ignores_lines_that_are_not_keys() {
        let fields = Fields::parse("junk\n%NAME%\nx\n\n%not-a-key%\ny\n\n%SHA256SUM%\nabc\n");
        assert_eq!(fields.first("NAME"), Some("x"));
        assert!(!fields.has("not-a-key"));
        assert_eq!(fields.first("SHA256SUM"), Some("abc"));
    }
}

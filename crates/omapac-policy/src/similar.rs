//! Typosquat detection: names within a small edit distance of a name the
//! user probably meant. Optimal string alignment distance (Damerau with
//! adjacent transpositions), which is what catches `firefox-patch-bin`
//! against `firefox-bin` style lookalikes.

/// Optimal string alignment distance between two strings.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

/// Names in `known` that `name` resembles: within distance `max` (but not
/// identical). Names and candidates shorter than four characters are skipped
/// because everything resembles them.
pub fn similar<'a>(
    name: &str,
    known: impl IntoIterator<Item = &'a str>,
    max: usize,
) -> Vec<String> {
    let mut found = Vec::new();
    if name.chars().count() < 4 {
        return found;
    }
    for candidate in known {
        // Three-letter names resemble everything; skip them as candidates.
        if candidate == name || candidate.chars().count() < 4 {
            continue;
        }
        if distance(name, candidate) <= max {
            found.push(candidate.to_string());
        }
    }
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distances() {
        assert_eq!(distance("", ""), 0);
        assert_eq!(distance("abc", "abc"), 0);
        assert_eq!(distance("abc", "acb"), 1, "transposition");
        assert_eq!(distance("abc", "abcd"), 1);
        assert_eq!(distance("kitten", "sitting"), 3);
        assert_eq!(distance("firefox", "firefx"), 1);
    }

    #[test]
    fn lookalikes() {
        let known = ["firefox", "firefox-bin", "helix", "python", "yay", "bat"];
        assert!(similar("firefox-bin", known, 2).is_empty());
        assert!(similar("python-requests", known, 2).is_empty());
        assert!(similar("firefox-patch-bin", known, 2).is_empty());
        assert_eq!(similar("firefx-bin", known, 2), ["firefox-bin"]);
        assert_eq!(similar("hellix", known, 2), ["helix"]);
        assert_eq!(
            similar("helix", known, 2),
            Vec::<String>::new(),
            "identical is fine"
        );
        assert!(
            similar("yay2", known, 2).is_empty(),
            "short names are skipped"
        );
        assert!(
            similar("batsignal", known, 2).is_empty(),
            "short candidates do not pad"
        );
        assert!(similar("something-else", known, 2).is_empty());
    }
}

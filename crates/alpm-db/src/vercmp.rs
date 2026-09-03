//! pacman's version comparison, ported from libalpm's `version.c`.
//!
//! A version is `[epoch:]pkgver[-pkgrel]`. Epochs compare first, then the
//! version, then the release, but only when both sides carry a release.
//! Each part is compared segment by segment with the rpm-derived algorithm:
//! runs of digits compare numerically, runs of letters compare as strings,
//! a numeric segment beats an alphabetic one, and separators only matter
//! when their lengths differ.
//!
//! This is a byte-for-byte port rather than a reinterpretation because
//! omapac must agree with `pacman -Qu` and `vercmp(8)` on every input.
//! Tests carry pacman's own vector table and, when a `vercmp` binary is on
//! the machine, a cross-check against it.

use std::cmp::Ordering;

/// Compare two full version strings the way `alpm_pkg_vercmp` does.
pub fn vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let a = Evr::parse(a);
    let b = Evr::parse(b);
    let by_epoch = rpmvercmp(a.epoch.as_bytes(), b.epoch.as_bytes());
    if by_epoch != Ordering::Equal {
        return by_epoch;
    }
    let by_version = rpmvercmp(a.version.as_bytes(), b.version.as_bytes());
    if by_version != Ordering::Equal {
        return by_version;
    }
    match (a.release, b.release) {
        (Some(ra), Some(rb)) => rpmvercmp(ra.as_bytes(), rb.as_bytes()),
        _ => Ordering::Equal,
    }
}

/// A version split into its epoch, version, and release parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evr<'a> {
    /// The epoch, `"0"` when the string carries none.
    pub epoch: &'a str,
    /// The pkgver.
    pub version: &'a str,
    /// The pkgrel, when present.
    pub release: Option<&'a str>,
}

impl<'a> Evr<'a> {
    /// Split `[epoch:]version[-release]` the way libalpm's `parseEVR` does.
    pub fn parse(evr: &'a str) -> Self {
        let bytes = evr.as_bytes();
        let digits_end = bytes
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(bytes.len());
        let (epoch, rest) = if bytes.get(digits_end) == Some(&b':') {
            let epoch = &evr[..digits_end];
            (
                if epoch.is_empty() { "0" } else { epoch },
                &evr[digits_end + 1..],
            )
        } else {
            ("0", evr)
        };
        // libalpm looks for the last '-' starting after the leading digits,
        // which is the same as looking in the remainder after the epoch.
        let (version, release) = match rest.rfind('-') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        Evr {
            epoch,
            version,
            release,
        }
    }
}

/// Compare the alpha and numeric segments of two version parts.
fn rpmvercmp(a: &[u8], b: &[u8]) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let mut one = 0;
    let mut two = 0;
    let mut ptr1 = 0;
    let mut ptr2 = 0;

    while one < a.len() && two < b.len() {
        while one < a.len() && !a[one].is_ascii_alphanumeric() {
            one += 1;
        }
        while two < b.len() && !b[two].is_ascii_alphanumeric() {
            two += 1;
        }
        if !(one < a.len() && two < b.len()) {
            break;
        }
        // Separator runs of different lengths decide the comparison.
        if (one - ptr1) != (two - ptr2) {
            return if (one - ptr1) < (two - ptr2) {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        ptr1 = one;
        ptr2 = two;

        let isnum = a[ptr1].is_ascii_digit();
        if isnum {
            while ptr1 < a.len() && a[ptr1].is_ascii_digit() {
                ptr1 += 1;
            }
            while ptr2 < b.len() && b[ptr2].is_ascii_digit() {
                ptr2 += 1;
            }
        } else {
            while ptr1 < a.len() && a[ptr1].is_ascii_alphabetic() {
                ptr1 += 1;
            }
            while ptr2 < b.len() && b[ptr2].is_ascii_alphabetic() {
                ptr2 += 1;
            }
        }
        let seg1 = &a[one..ptr1];
        let seg2 = &b[two..ptr2];
        if seg1.is_empty() {
            // Cannot happen: the first string has a non-empty segment here.
            return Ordering::Less;
        }
        if seg2.is_empty() {
            // Different segment types: numeric is always newer than alpha.
            return if isnum {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let ordering = if isnum {
            let n1 = strip_leading_zeros(seg1);
            let n2 = strip_leading_zeros(seg2);
            match n1.len().cmp(&n2.len()) {
                Ordering::Equal => n1.cmp(n2),
                longer => longer,
            }
        } else {
            seg1.cmp(seg2)
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
        one = ptr1;
        two = ptr2;
    }

    if one >= a.len() && two >= b.len() {
        return Ordering::Equal;
    }
    // The final showdown: a remaining alpha string never beats an empty one.
    let one_empty = one >= a.len();
    let one_alpha = one < a.len() && a[one].is_ascii_alphabetic();
    let two_alpha = two < b.len() && b[two].is_ascii_alphabetic();
    if (one_empty && !two_alpha) || one_alpha {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

fn strip_leading_zeros(digits: &[u8]) -> &[u8] {
    let start = digits
        .iter()
        .position(|b| *b != b'0')
        .unwrap_or(digits.len());
    &digits[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pacman's `test/util/vercmptest.sh`, verbatim. Each row is also run
    /// mirrored, as that script does.
    const VECTORS: &[(&str, &str, i8)] = &[
        ("1.5.0", "1.5.0", 0),
        ("1.5.1", "1.5.0", 1),
        ("1.5.1", "1.5", 1),
        ("1.5.0-1", "1.5.0-1", 0),
        ("1.5.0-1", "1.5.0-2", -1),
        ("1.5.0-1", "1.5.1-1", -1),
        ("1.5.0-2", "1.5.1-1", -1),
        ("1.5-1", "1.5.1-1", -1),
        ("1.5-2", "1.5.1-1", -1),
        ("1.5-2", "1.5.1-2", -1),
        ("1.5", "1.5-1", 0),
        ("1.5-1", "1.5", 0),
        ("1.1-1", "1.1", 0),
        ("1.0-1", "1.1", -1),
        ("1.1-1", "1.0", 1),
        ("1.5b-1", "1.5-1", -1),
        ("1.5b", "1.5", -1),
        ("1.5b-1", "1.5", -1),
        ("1.5b", "1.5.1", -1),
        ("1.0a", "1.0alpha", -1),
        ("1.0alpha", "1.0b", -1),
        ("1.0b", "1.0beta", -1),
        ("1.0beta", "1.0rc", -1),
        ("1.0rc", "1.0", -1),
        ("1.5.a", "1.5", 1),
        ("1.5.b", "1.5.a", 1),
        ("1.5.1", "1.5.b", 1),
        ("1.5.b-1", "1.5.b", 0),
        ("1.5-1", "1.5.b", -1),
        ("2.0", "2_0", 0),
        ("2.0_a", "2_0.a", 0),
        ("2.0a", "2.0.a", -1),
        ("2___a", "2_a", 1),
        ("0:1.0", "0:1.0", 0),
        ("0:1.0", "0:1.1", -1),
        ("1:1.0", "0:1.0", 1),
        ("1:1.0", "0:1.1", 1),
        ("1:1.0", "2:1.1", -1),
        ("1:1.0", "0:1.0-1", 1),
        ("1:1.0-1", "0:1.1-1", 1),
        ("0:1.0", "1.0", 0),
        ("0:1.0", "1.1", -1),
        ("0:1.1", "1.0", 1),
        ("1:1.0", "1.0", 1),
        ("1:1.0", "1.1", 1),
        ("1:1.1", "1.1", 1),
    ];

    fn sign(o: Ordering) -> i8 {
        match o {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    #[test]
    fn pacman_vector_table() {
        for (a, b, expected) in VECTORS {
            assert_eq!(sign(vercmp(a, b)), *expected, "vercmp({a}, {b})");
            assert_eq!(sign(vercmp(b, a)), -expected, "vercmp({b}, {a}) mirrored");
        }
    }

    #[test]
    fn evr_parsing() {
        assert_eq!(
            Evr::parse("2:1.5.0-3"),
            Evr {
                epoch: "2",
                version: "1.5.0",
                release: Some("3")
            }
        );
        assert_eq!(
            Evr::parse("1.5.0"),
            Evr {
                epoch: "0",
                version: "1.5.0",
                release: None
            }
        );
        assert_eq!(
            Evr::parse(":1.0-1"),
            Evr {
                epoch: "0",
                version: "1.0",
                release: Some("1")
            }
        );
        assert_eq!(
            Evr::parse("2026.09.03.r12.gabcdef0-1"),
            Evr {
                epoch: "0",
                version: "2026.09.03.r12.gabcdef0",
                release: Some("1")
            }
        );
        assert_eq!(
            Evr::parse("1.0-2-3"),
            Evr {
                epoch: "0",
                version: "1.0-2",
                release: Some("3")
            }
        );
    }

    #[test]
    fn empty_and_odd_inputs_do_not_panic() {
        assert_eq!(vercmp("", ""), Ordering::Equal);
        assert_eq!(vercmp("", "1"), Ordering::Less);
        assert_eq!(vercmp("1", ""), Ordering::Greater);
        // libalpm: a remaining alpha string never beats an empty string.
        assert_eq!(vercmp("", "a"), Ordering::Greater);
        assert_eq!(vercmp("...", "..."), Ordering::Equal);
        assert_eq!(vercmp("1..2", "1.2"), Ordering::Greater);
        assert_eq!(vercmp("00", "0"), Ordering::Equal);
        assert_eq!(vercmp("0010", "10"), Ordering::Equal);
        assert_eq!(
            vercmp("99999999999999999999", "100000000000000000000"),
            Ordering::Less
        );
        assert_eq!(vercmp("1.0-r1", "1.0"), Ordering::Equal);
        assert_eq!(vercmp("1.0.0-1", "1.0.0-1.1"), Ordering::Less);
    }

    /// Cross-check against the real `vercmp` binary when one is installed.
    /// Skipped silently elsewhere; CI runs it in an Arch container.
    #[test]
    fn agrees_with_the_vercmp_binary_when_present() {
        let bin = std::env::var("OMAPAC_VERCMP_BIN").unwrap_or_else(|_| "vercmp".to_string());
        if std::process::Command::new(&bin)
            .args(["1", "1"])
            .output()
            .is_err()
        {
            eprintln!("skipping: no vercmp binary");
            return;
        }
        let versions = [
            "1",
            "1.0",
            "1.0.0",
            "1.0a",
            "1.0.a",
            "1.0-1",
            "1.0-2",
            "1:1.0",
            "2:0.9",
            "1.0rc1",
            "1.0beta",
            "1.0.0.0",
            "1_0",
            "1..0",
            "01",
            "10",
            "1.10",
            "1.9",
            "a",
            "b",
            "1a",
            "a1",
            "2026.09.03",
            "20260903",
            "r123.gabc",
            "1.0-1.1",
            "0",
            "",
            "1.0.0-r1",
            "1.0.0.r1",
        ];
        for a in versions {
            for b in versions {
                let out = std::process::Command::new(&bin)
                    .args([a, b])
                    .output()
                    .expect("vercmp runs");
                let expected: i8 = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .parse()
                    .expect("vercmp prints -1, 0, or 1");
                assert_eq!(sign(vercmp(a, b)), expected, "vercmp({a:?}, {b:?})");
            }
        }
    }
}

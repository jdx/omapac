//! The mise backend plugin end to end: link it into an isolated mise,
//! list versions from a local channel, and install one. Skipped when no
//! mise binary is on PATH.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

fn mise_binary() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("mise"))
        .find(|candidate| candidate.is_file())
}

struct Mise {
    binary: PathBuf,
    home: PathBuf,
    project: PathBuf,
    path: String,
}

impl Mise {
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
        let mut cmd = Command::new(&self.binary);
        cmd.current_dir(&self.project)
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .env("MISE_DATA_DIR", self.home.join("data"))
            .env("MISE_CONFIG_DIR", self.home.join("config"))
            .env("MISE_CACHE_DIR", self.home.join("cache"))
            .env("MISE_STATE_DIR", self.home.join("state"))
            .env("MISE_TRUSTED_CONFIG_PATHS", &self.project)
            .env("MISE_YES", "1")
            .env("XDG_CACHE_HOME", self.home.join("xdg-cache"))
            .args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let output = cmd.output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

#[test]
fn plugin_lists_and_installs_through_omapac() {
    let Some(binary) = mise_binary() else {
        eprintln!("skipping: no mise on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let store = common::tools::build_store(dir.path(), false);
    let home = dir.path().join("home");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let omapac_dir = Path::new(env!("CARGO_BIN_EXE_omapac"))
        .parent()
        .unwrap()
        .to_path_buf();
    let mise = Mise {
        binary,
        home,
        project,
        path: format!("{}:/usr/bin:/bin", omapac_dir.display()),
    };
    let plugin = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins/mise-tool-channel");
    let channel_env = [
        ("OMAPAC_TOOLS_BASE", store.base.as_str()),
        ("OMAPAC_TOOLS_PUBKEY", store.channel_pub.to_str().unwrap()),
    ];

    let (code, out, err) = mise.run(
        &["plugin", "link", "tool-channel", plugin.to_str().unwrap()],
        &[],
    );
    assert_eq!(code, 0, "{out}\n{err}");

    // Stable by default; edge when asked.
    let (code, out, err) = mise.run(&["ls-remote", "tool-channel:tool"], &channel_env);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(out.trim(), "1.0.0", "{out}\n{err}");
    let mut edge = channel_env.to_vec();
    edge.push(("OMAPAC_TOOLS_CHANNEL", "edge"));
    let (code, out, err) = mise.run(&["ls-remote", "tool-channel:tool"], &edge);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(
        out.trim(),
        "1.0.0\n1.2.0",
        "held excluded, oldest first: {out}\n{err}"
    );

    // Install: the artifact in the test store is a bare file, so it lands
    // as bin/<tool>.
    let (code, out, err) = mise.run(&["install", "tool-channel:tool@1.0.0"], &channel_env);
    assert_eq!(code, 0, "{out}\n{err}");
    let installed = mise
        .home
        .join("data/installs/tool-channel-tool/1.0.0/bin/tool");
    assert!(installed.is_file(), "{}", installed.display());
    assert_eq!(
        std::fs::read_to_string(&installed).unwrap(),
        "bytes of 1.0.0"
    );
    let (code, out, err) = mise.run(&["ls", "tool-channel:tool"], &channel_env);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("1.0.0"), "{out}");

    // An archive: extracted with the top-level directory stripped, and
    // bin/tool found and linked.
    let (code, out, err) = mise.run(&["install", "tool-channel:tool@1.2.0"], &edge);
    assert_eq!(code, 0, "{out}\n{err}");
    let linked = mise
        .home
        .join("data/installs/tool-channel-tool/1.2.0/bin/tool");
    assert_eq!(std::fs::read_to_string(&linked).unwrap(), "archived 1.2.0");

    // A held version is refused by omapac, so mise reports the failure.
    let (code, out, err) = mise.run(&["install", "tool-channel:tool@1.1.0"], &channel_env);
    assert_ne!(code, 0, "{out}");
    assert!(err.contains("is held by the channel: regression"), "{err}");
}

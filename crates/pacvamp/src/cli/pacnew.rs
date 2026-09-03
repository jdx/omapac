use eyre::{Result, bail};
use usage_rs::RunWith;

use super::{App, print_json};
use crate::update::pacnew_files;

/// List .pacnew and .pacsave files under /etc, and show their diffs
///
/// pacman leaves a .pacnew beside a configuration file you changed when
/// the package ships a new default, and a .pacsave when a package that
/// owned a file is removed. Nothing is merged for you here.
#[derive(Debug, usage_rs::Args)]
pub struct Pacnew {
    /// Show a unified diff of each pair
    #[usage(short = 'd', long)]
    diff: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<&App> for Pacnew {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let etc = app
            .paths
            .sysroot
            .as_ref()
            .map(|r| r.join("etc"))
            .unwrap_or_else(|| "/etc".into());
        let files = pacnew_files(&etc);
        if self.json {
            return print_json(&files);
        }
        if files.is_empty() {
            println!("no .pacnew or .pacsave files under {}", etc.display());
            return Ok(());
        }
        for file in &files {
            println!("{}", file.display());
            if self.diff {
                let original = file.with_extension("");
                let output = std::process::Command::new("diff")
                    .arg("-u")
                    .arg(&original)
                    .arg(file)
                    .output();
                match output {
                    Ok(out) if matches!(out.status.code(), Some(0 | 1)) => {
                        print!("{}", String::from_utf8_lossy(&out.stdout));
                    }
                    Ok(out) => bail!(
                        "diffing {} against {} failed: {}",
                        file.display(),
                        original.display(),
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                    Err(err) => bail!("running diff: {err}"),
                }
            }
        }
        Ok(())
    }
}

use alpm_db::Dependency;
use eyre::Result;
use usage_rs::RunWith;

use super::App;
use crate::host::Host;

/// Exit 0 when every named package is installed, else 1
///
/// A name is satisfied by an installed package of that name or by one
/// that provides it, and may carry a version constraint such as
/// `pacman>=7`. Prints nothing; for menu guards and scripts.
#[derive(Debug, usage_rs::Args)]
pub struct Present {
    /// Package names, optionally with a version constraint
    #[usage(required = true)]
    packages: Vec<String>,
}

/// Exit 0 when none of the named packages is installed, else 1
///
/// The complement of `present`, with the same matching rules.
#[derive(Debug, usage_rs::Args)]
pub struct Missing {
    /// Package names, optionally with a version constraint
    #[usage(required = true)]
    packages: Vec<String>,
}

/// Which of `names` are satisfied on the host.
pub fn satisfied(host: &Host, names: &[String]) -> Result<Vec<bool>> {
    names
        .iter()
        .map(|name| host.is_satisfied(&Dependency::parse(name)))
        .collect()
}

impl RunWith<&App> for Present {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let all = satisfied(&host, &self.packages)?.into_iter().all(|s| s);
        if !all {
            std::process::exit(1);
        }
        Ok(())
    }
}

impl RunWith<&App> for Missing {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let none = satisfied(&host, &self.packages)?.into_iter().all(|s| !s);
        if !none {
            std::process::exit(1);
        }
        Ok(())
    }
}

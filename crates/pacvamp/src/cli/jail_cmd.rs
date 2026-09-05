use std::io::Read as _;
use std::os::unix::process::CommandExt as _;

use eyre::{Context as _, Result};
use usage_rs::RunWith;

use super::App;
use crate::jail::Spec;

/// Restrict this process per a JSON spec on stdin, then exec the command
#[derive(Debug, usage_rs::Args)]
pub struct JailExec {}

impl RunWith<&App> for JailExec {
    type Output = Result<()>;

    fn run_with(self, _app: &App) -> Self::Output {
        let mut json = String::new();
        std::io::stdin()
            .read_to_string(&mut json)
            .wrap_err("reading the jail spec from stdin")?;
        let spec: Spec = serde_json::from_str(&json).wrap_err("parsing the jail spec")?;
        spec.apply()?;
        let mut command = std::process::Command::new(&spec.program);
        command
            .args(&spec.args)
            .current_dir(&spec.cwd)
            .stdin(std::process::Stdio::null());
        // exec only returns on failure.
        let err = command.exec();
        Err(err).wrap_err_with(|| format!("executing {}", spec.program.display()))
    }
}

/// Apply build limits and optional filesystem confinement, then execute
#[derive(Debug, usage_rs::Args)]
pub struct BuildExec {}
impl RunWith<&App> for BuildExec {
    type Output = Result<()>;
    fn run_with(self, _app: &App) -> Result<()> {
        let request: crate::build_process::BuildSpec = serde_json::from_reader(std::io::stdin())?;
        if let Some(path) = &request.cgroup_path {
            crate::cgroup::join(path)?;
        }
        request.limits.apply()?;
        if request.jail {
            request.spec.apply()?;
        }
        crate::build_process::confine_process_group()?;
        let mut command = std::process::Command::new(&request.spec.program);
        let err = command
            .args(&request.spec.args)
            .current_dir(&request.spec.cwd)
            .stdin(std::process::Stdio::null())
            .exec();
        Err(err).wrap_err("executing build command")
    }
}

/// Kill a delegated build cgroup when the supervisor's pipe closes
#[derive(Debug, usage_rs::Args)]
pub struct CgroupWatch {
    path: std::path::PathBuf,
}
impl RunWith<&App> for CgroupWatch {
    type Output = Result<()>;
    fn run_with(self, _: &App) -> Result<()> {
        crate::cgroup::watch(&self.path)
    }
}

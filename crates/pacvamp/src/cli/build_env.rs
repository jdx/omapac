use super::App;
use crate::aur::environment;
use eyre::Result;
use std::path::PathBuf;
use usage_rs::RunWith;
/// Provision Arch build images with devtools
#[derive(Debug, usage_rs::Args)]
pub struct BuildEnv {
    #[usage(subcommand)]
    command: Commands,
}
#[derive(Debug, usage_rs::Subcommands)]
#[usage(run_with)]
enum Commands {
    Init(Init),
    Update(Update),
}
/// Create a new base-devel image; requires devtools and root privileges
#[derive(Debug, usage_rs::Args)]
pub struct Init {
    root: PathBuf,
    /// Additional repository packages
    #[usage(long)]
    package: Vec<String>,
}
/// Clone and update an image into a new destination, preserving the original
#[derive(Debug, usage_rs::Args)]
pub struct Update {
    root: PathBuf,
    #[usage(long)]
    destination: PathBuf,
    #[usage(long)]
    package: Vec<String>,
    #[usage(short = 'y', long)]
    yes: bool,
}
impl RunWith<&App> for BuildEnv {
    type Output = Result<()>;
    fn run_with(self, app: &App) -> Result<()> {
        self.command.run_with(app)
    }
}
impl RunWith<&App> for Init {
    type Output = Result<()>;
    fn run_with(self, _: &App) -> Result<()> {
        environment::initialize(&self.root, &self.package)
    }
}
impl RunWith<&App> for Update {
    type Output = Result<()>;
    fn run_with(self, _: &App) -> Result<()> {
        environment::validate_packages(&self.package)?;
        environment::clone_image(&self.root, &self.destination)?;
        environment::update(&self.destination, &self.package, self.yes)
    }
}

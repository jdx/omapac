#![forbid(unsafe_code)]

mod cli;

use std::ffi::OsString;

use eyre::Result;

fn main() -> Result<()> {
    color_eyre::install()?;
    let argv: Vec<OsString> = std::env::args_os().collect();
    cli::run(&argv)
}

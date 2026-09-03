#![forbid(unsafe_code)]

use std::ffi::OsString;

use eyre::Result;

fn main() -> Result<()> {
    color_eyre::install()?;
    let argv: Vec<OsString> = std::env::args_os().collect();
    pacvamp::cli::run(&argv)
}

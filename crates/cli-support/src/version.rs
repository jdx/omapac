use eyre::Result;
use usage_rs::RunWith;

/// Show the version
#[derive(Debug, usage_rs::Args)]
#[usage(visible_alias = "v")]
pub struct Version {
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

/// The binary's identity, handed to commands that print it.
#[derive(Debug, Clone, Copy)]
pub struct BinInfo {
    pub name: &'static str,
    pub version: &'static str,
}

impl RunWith<BinInfo> for Version {
    type Output = Result<()>;

    fn run_with(self, bin: BinInfo) -> Self::Output {
        if self.json {
            let json = serde_json::json!({
                "name": bin.name,
                "version": bin.version,
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        } else {
            println!("{} {}", bin.name, bin.version);
        }
        Ok(())
    }
}

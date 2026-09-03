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

impl AsRef<BinInfo> for BinInfo {
    fn as_ref(&self) -> &BinInfo {
        self
    }
}

/// Any context that can hand over a [`BinInfo`] can run `version`, so a
/// binary's own context struct works as the dispatch context.
impl<Ctx: AsRef<BinInfo>> RunWith<Ctx> for Version {
    type Output = Result<()>;

    fn run_with(self, ctx: Ctx) -> Self::Output {
        let bin = ctx.as_ref();
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

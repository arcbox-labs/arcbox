pub mod boot_assets;

use anyhow::Result;

use crate::{TestArgs, TestCommand};

pub fn run(args: TestArgs) -> Result<()> {
    match args.command {
        TestCommand::BootAssets(args) => boot_assets::run(args),
    }
}

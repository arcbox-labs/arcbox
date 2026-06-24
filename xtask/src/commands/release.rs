pub mod check_tool_updates;
pub mod package_tarball;

use anyhow::Result;

use crate::{ReleaseArgs, ReleaseCommand};

pub fn run(args: ReleaseArgs) -> Result<()> {
    match args.command {
        ReleaseCommand::CheckToolUpdates(args) => check_tool_updates::run(args),
        ReleaseCommand::PackageTarball(args) => package_tarball::run(args),
    }
}

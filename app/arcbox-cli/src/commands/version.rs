//! Version command implementation.

use super::OutputFormat;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct VersionOutput {
    arcbox_core_abctl_version: &'static str,
    default_compatible_boot_assets_version: &'static str,
    minimum_compatible_helper_version: &'static str,
    os: &'static str,
    arch: &'static str,
}

impl VersionOutput {
    fn current() -> Self {
        Self {
            arcbox_core_abctl_version: env!("CARGO_PKG_VERSION"),
            default_compatible_boot_assets_version: arcbox_core::boot_asset_version(),
            minimum_compatible_helper_version: arcbox_constants::helper::MIN_HELPER_VERSION,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        }
    }
}

/// Executes the version command.
pub async fn execute(format: OutputFormat) -> Result<()> {
    let output = VersionOutput::current();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(&output)?),
        OutputFormat::Table | OutputFormat::Quiet => println!("{}", render_human(&output)),
    }

    Ok(())
}

fn render_human(output: &VersionOutput) -> String {
    format!(
        "ArcBox components\n\
         ArcBox Core / abctl (local build): {}\n\
         Boot assets (default compatible): {}\n\
         arcbox-helper (minimum compatible): {}\n\
         Platform: {} / {}\n\n\
         For current and latest boot assets, run 'abctl boot status'.",
        output.arcbox_core_abctl_version,
        output.default_compatible_boot_assets_version,
        output.minimum_compatible_helper_version,
        output.os,
        output.arch,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_output_names_component_version_roles() {
        let rendered = render_human(&VersionOutput::current());

        assert!(rendered.contains("ArcBox Core / abctl (local build):"));
        assert!(rendered.contains("Boot assets (default compatible):"));
        assert!(rendered.contains("arcbox-helper (minimum compatible):"));
        assert!(rendered.contains("run 'abctl boot status'"));
        assert!(!rendered.contains("Rust:"));
        assert!(!rendered.contains("unknown"));
    }

    #[test]
    fn json_output_has_stable_component_fields() {
        let value = serde_json::to_value(VersionOutput::current()).unwrap();

        assert_eq!(
            value["arcbox_core_abctl_version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            value["default_compatible_boot_assets_version"],
            arcbox_core::boot_asset_version()
        );
        assert_eq!(
            value["minimum_compatible_helper_version"],
            arcbox_constants::helper::MIN_HELPER_VERSION
        );
        assert_eq!(value["os"], std::env::consts::OS);
        assert_eq!(value["arch"], std::env::consts::ARCH);
        assert!(value.get("rust").is_none());
    }
}

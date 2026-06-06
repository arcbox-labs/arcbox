//! Print the latest supported macOS restore image (IPSW) download URL.
//!
//! ```sh
//! cargo run -p arcbox-vz --example macos_latest_url
//! ```

use std::error::Error;

use arcbox_vz::MacOSRestoreImage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if !arcbox_vz::is_supported() {
        eprintln!("Virtualization is not supported on this host (Apple Silicon required).");
        return Ok(());
    }
    let restore = MacOSRestoreImage::latest_supported().await?;
    match restore.url() {
        Some(url) => println!("{url}"),
        None => return Err("restore image exposes no URL".into()),
    }
    Ok(())
}

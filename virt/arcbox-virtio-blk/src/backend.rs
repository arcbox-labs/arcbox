//! Async block I/O backend trait.

/// Async block I/O backend trait.
#[async_trait::async_trait]
pub trait AsyncBlockBackend: Send + Sync {
    /// Reads data from the given sector.
    async fn read(&self, sector: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Writes data to the given sector.
    async fn write(&self, sector: u64, buf: &[u8]) -> std::io::Result<usize>;

    /// Flushes pending writes.
    async fn flush(&self) -> std::io::Result<()>;

    /// Returns the capacity in sectors.
    fn capacity(&self) -> u64;

    /// Returns whether the device is read-only.
    fn is_read_only(&self) -> bool;
}

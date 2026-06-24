use super::SnapshotError;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

/// Compresses data with LZ4 and writes to file.
pub(super) fn compress_and_write(path: &Path, data: &[u8]) -> Result<(), SnapshotError> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    // Use lz4_flex for compression.
    let compressed = lz4_flex::compress_prepend_size(data);

    writer
        .write_all(&compressed)
        .map_err(|e| SnapshotError::CompressionError(e.to_string()))?;

    writer.flush()?;
    Ok(())
}

/// Reads and decompresses LZ4 data from file.
pub(super) fn read_and_decompress(path: &Path) -> Result<Vec<u8>, SnapshotError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut compressed = Vec::new();
    reader.read_to_end(&mut compressed)?;

    lz4_flex::decompress_size_prepended(&compressed)
        .map_err(|e| SnapshotError::CompressionError(e.to_string()))
}

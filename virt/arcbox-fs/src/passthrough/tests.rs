use std::ffi::OsStr;
use std::path::Path;

use tempfile::TempDir;

use super::*;

const S_IFDIR: u32 = libc::S_IFDIR as u32;
const S_IFREG: u32 = libc::S_IFREG as u32;

fn setup_test_fs() -> (TempDir, PassthroughFs) {
    let temp = TempDir::new().expect("failed to create temp dir");
    let fs = PassthroughFs::new(temp.path()).expect("failed to create fs");
    (temp, fs)
}

#[test]
fn test_new_filesystem() {
    let temp = TempDir::new().unwrap();
    let fs = PassthroughFs::new(temp.path()).unwrap();
    assert_eq!(fs.root(), temp.path());
}

#[test]
fn test_new_invalid_path() {
    let result = PassthroughFs::new("/nonexistent/path/12345");
    assert!(result.is_err());
}

#[test]
fn test_lookup_existing_file() {
    let (temp, fs) = setup_test_fs();

    // Create a test file
    let file_path = temp.path().join("test.txt");
    std::fs::write(&file_path, "hello").unwrap();

    // Lookup should succeed
    let result = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("test.txt"));
    assert!(result.is_ok());
    let (inode, attr) = result.unwrap();
    assert!(inode > PassthroughFs::ROOT_INODE);
    assert_eq!(attr.size, 5);
}

#[test]
fn test_lookup_nonexistent_file() {
    let (_temp, fs) = setup_test_fs();

    let result = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("nonexistent.txt"));
    assert!(result.is_err());
    assert!(result.unwrap_err().is_not_found());
}

#[test]
fn test_lookup_negative_cache() {
    let (_temp, fs) = setup_test_fs();

    // First lookup - should miss
    let _ = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("missing.txt"));

    // Check stats
    if let Some(cache) = fs.negative_cache() {
        let stats = cache.stats();
        assert!(stats.entries > 0 || stats.misses > 0);
    }

    // Second lookup - should hit cache
    let result = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("missing.txt"));
    assert!(result.is_err());
    assert!(result.unwrap_err().is_not_found());
}

#[test]
fn test_getattr_root() {
    let (_temp, fs) = setup_test_fs();

    let result = fs.getattr(PassthroughFs::ROOT_INODE);
    assert!(result.is_ok());
    let attr = result.unwrap();
    assert_eq!(attr.ino, PassthroughFs::ROOT_INODE);
    assert!(attr.mode & S_IFDIR != 0);
}

#[test]
fn test_create_and_read_file() {
    let (_temp, fs) = setup_test_fs();

    // Create file
    let (inode, _attr, handle) = fs
        .create(
            PassthroughFs::ROOT_INODE,
            OsStr::new("newfile.txt"),
            0o644,
            libc::O_RDWR as u32,
        )
        .unwrap();

    assert!(inode > PassthroughFs::ROOT_INODE);

    // Write to file
    let data = b"hello world";
    let written = fs.write(handle, 0, data, 0).unwrap();
    assert_eq!(written, data.len() as u32);

    // Read back
    let read_data = fs.read(handle, 0, 100).unwrap();
    assert_eq!(read_data, data);

    // Release handle
    fs.release(handle).unwrap();
}

#[test]
fn test_mkdir_and_rmdir() {
    let (_temp, fs) = setup_test_fs();

    // Create directory
    let (inode, attr) = fs
        .mkdir(PassthroughFs::ROOT_INODE, OsStr::new("testdir"), 0o755)
        .unwrap();

    assert!(inode > PassthroughFs::ROOT_INODE);
    assert!(attr.mode & S_IFDIR != 0);

    // Remove directory
    fs.rmdir(PassthroughFs::ROOT_INODE, OsStr::new("testdir"))
        .unwrap();

    // Lookup should fail
    let result = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("testdir"));
    assert!(result.is_err());
    assert!(result.unwrap_err().is_not_found());
}

#[test]
fn test_symlink_and_readlink() {
    let (temp, fs) = setup_test_fs();

    // Create a target file
    let target = temp.path().join("target.txt");
    std::fs::write(&target, "target content").unwrap();

    // Create symlink
    let (inode, _attr) = fs
        .symlink(
            PassthroughFs::ROOT_INODE,
            OsStr::new("link"),
            Path::new("target.txt"),
        )
        .unwrap();

    // Read link
    let link_target = fs.readlink(inode).unwrap();
    assert_eq!(link_target, Path::new("target.txt"));
}

#[test]
fn test_hard_link() {
    let (temp, fs) = setup_test_fs();

    // Create original file
    let original = temp.path().join("original.txt");
    std::fs::write(&original, "content").unwrap();

    // Lookup original
    let (orig_inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("original.txt"))
        .unwrap();

    // Create hard link
    let (link_inode, attr) = fs
        .link(
            orig_inode,
            PassthroughFs::ROOT_INODE,
            OsStr::new("hardlink.txt"),
        )
        .unwrap();

    // Hard links share the same inode
    assert_eq!(link_inode, orig_inode);
    assert!(attr.nlink >= 2);
}

#[test]
fn test_unlink() {
    let (temp, fs) = setup_test_fs();

    // Create file
    let file_path = temp.path().join("todelete.txt");
    std::fs::write(&file_path, "delete me").unwrap();

    // Unlink
    fs.unlink(PassthroughFs::ROOT_INODE, OsStr::new("todelete.txt"))
        .unwrap();

    // File should be gone
    assert!(!file_path.exists());
}

#[test]
fn test_rename() {
    let (temp, fs) = setup_test_fs();

    // Create file
    let old_path = temp.path().join("old.txt");
    std::fs::write(&old_path, "content").unwrap();

    // Rename
    fs.rename(
        PassthroughFs::ROOT_INODE,
        OsStr::new("old.txt"),
        PassthroughFs::ROOT_INODE,
        OsStr::new("new.txt"),
        0,
    )
    .unwrap();

    // Old path should not exist
    assert!(!old_path.exists());
    // New path should exist
    assert!(temp.path().join("new.txt").exists());
}

#[test]
fn test_opendir_readdir() {
    let (temp, fs) = setup_test_fs();

    // Create some files
    std::fs::write(temp.path().join("file1.txt"), "1").unwrap();
    std::fs::write(temp.path().join("file2.txt"), "2").unwrap();
    std::fs::create_dir(temp.path().join("subdir")).unwrap();

    // Open directory
    let handle = fs.opendir(PassthroughFs::ROOT_INODE).unwrap();

    // Read entries
    let entries = fs.readdir(handle, 0).unwrap();

    // Should have at least . .. and our 3 entries
    assert!(entries.len() >= 5);

    // Check for expected names
    let names: Vec<_> = entries
        .iter()
        .map(|e| e.name.to_string_lossy().to_string())
        .collect();
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert!(names.contains(&"file1.txt".to_string()));
    assert!(names.contains(&"file2.txt".to_string()));
    assert!(names.contains(&"subdir".to_string()));

    // Release
    fs.releasedir(handle).unwrap();
}

#[test]
fn test_setattr_size() {
    let (temp, fs) = setup_test_fs();

    // Create file with content
    let file_path = temp.path().join("truncate.txt");
    std::fs::write(&file_path, "hello world").unwrap();

    let (inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("truncate.txt"))
        .unwrap();

    // Truncate to 5 bytes
    let attr = fs
        .setattr(inode, None, None, None, Some(5), None, None)
        .unwrap();
    assert_eq!(attr.size, 5);

    // Verify content
    let content = std::fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, "hello");
}

#[test]
fn test_setattr_mode() {
    let (temp, fs) = setup_test_fs();

    let file_path = temp.path().join("chmod.txt");
    std::fs::write(&file_path, "test").unwrap();

    let (inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("chmod.txt"))
        .unwrap();

    // Change mode
    let attr = fs
        .setattr(inode, Some(0o600), None, None, None, None, None)
        .unwrap();
    assert_eq!(attr.mode & 0o777, 0o600);
}

#[test]
fn test_open_read_write() {
    let (temp, fs) = setup_test_fs();

    // Create file
    let file_path = temp.path().join("rw.txt");
    std::fs::write(&file_path, "initial").unwrap();

    let (inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("rw.txt"))
        .unwrap();

    // Open for read/write
    let handle = fs.open(inode, libc::O_RDWR as u32).unwrap();

    // Read
    let data = fs.read(handle, 0, 100).unwrap();
    assert_eq!(data, b"initial");

    // Write at offset
    fs.write(handle, 0, b"INITIAL", 0).unwrap();

    // Read again
    let data = fs.read(handle, 0, 100).unwrap();
    assert_eq!(data, b"INITIAL");

    fs.release(handle).unwrap();
}

#[test]
fn test_fsync() {
    let (temp, fs) = setup_test_fs();

    let file_path = temp.path().join("sync.txt");
    std::fs::write(&file_path, "test").unwrap();

    let (inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("sync.txt"))
        .unwrap();

    let handle = fs.open(inode, libc::O_RDWR as u32).unwrap();
    fs.write(handle, 0, b"updated", 0).unwrap();

    // Sync should succeed
    fs.fsync(handle, false).unwrap();
    fs.fsync(handle, true).unwrap();

    fs.release(handle).unwrap();
}

#[test]
fn test_flush() {
    let (temp, fs) = setup_test_fs();

    let file_path = temp.path().join("flush.txt");
    std::fs::write(&file_path, "test").unwrap();

    let (inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("flush.txt"))
        .unwrap();

    let handle = fs.open(inode, libc::O_RDWR as u32).unwrap();
    fs.write(handle, 0, b"updated", 0).unwrap();
    fs.flush(handle).unwrap();
    fs.release(handle).unwrap();
}

#[test]
fn test_lseek() {
    let (temp, fs) = setup_test_fs();

    let file_path = temp.path().join("seek.txt");
    std::fs::write(&file_path, "0123456789").unwrap();

    let (inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("seek.txt"))
        .unwrap();

    let handle = fs.open(inode, libc::O_RDONLY as u32).unwrap();

    // Seek to offset 5
    let pos = fs.lseek(handle, 5, 0).unwrap(); // SEEK_SET
    assert_eq!(pos, 5);

    // Read from there
    let data = fs.read(handle, pos, 5).unwrap();
    assert_eq!(data, b"56789");

    fs.release(handle).unwrap();
}

#[test]
fn test_statfs() {
    let (_temp, fs) = setup_test_fs();

    let stat = fs.statfs().unwrap();
    assert!(stat.blocks > 0);
    assert!(stat.bsize > 0);
}

#[test]
fn test_access() {
    let (temp, fs) = setup_test_fs();

    let file_path = temp.path().join("access.txt");
    std::fs::write(&file_path, "test").unwrap();

    let (inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("access.txt"))
        .unwrap();

    // Should be readable
    fs.access(inode, libc::R_OK as u32).unwrap();

    // Should be writable
    fs.access(inode, libc::W_OK as u32).unwrap();
}

#[test]
fn test_forget() {
    let (temp, fs) = setup_test_fs();

    let file_path = temp.path().join("forget.txt");
    std::fs::write(&file_path, "test").unwrap();

    let (inode, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("forget.txt"))
        .unwrap();

    // Lookup again to increase refcount
    let (inode2, _) = fs
        .lookup(PassthroughFs::ROOT_INODE, OsStr::new("forget.txt"))
        .unwrap();
    assert_eq!(inode, inode2);

    // Forget once
    fs.forget(inode, 1);

    // Should still be in table
    assert!(fs.getattr(inode).is_ok());

    // Forget again
    fs.forget(inode, 1);

    // May or may not be removed depending on timing
}

#[test]
#[ignore = "mknod requires elevated permissions on macOS"]
fn test_mknod_regular_file() {
    let (_temp, fs) = setup_test_fs();

    // Create regular file via mknod
    let (inode, attr) = fs
        .mknod(
            PassthroughFs::ROOT_INODE,
            OsStr::new("mknod_file"),
            S_IFREG | 0o644,
            0,
        )
        .unwrap();

    assert!(inode > PassthroughFs::ROOT_INODE);
    assert!(attr.mode & S_IFREG != 0);
}

#[test]
fn test_concurrent_operations() {
    use std::sync::Arc;
    use std::thread;

    let (temp, fs) = setup_test_fs();
    let fs = Arc::new(fs);

    // Create some initial files
    for i in 0..10 {
        std::fs::write(
            temp.path().join(format!("file{i}.txt")),
            format!("content{i}"),
        )
        .unwrap();
    }

    let mut handles = vec![];

    // Spawn threads doing lookups
    for i in 0..4 {
        let fs = Arc::clone(&fs);
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                let name = format!("file{}.txt", (i + j) % 10);
                let _ = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new(&name));
            }
        }));
    }

    // Spawn threads doing reads
    for i in 0..4 {
        let fs = Arc::clone(&fs);
        handles.push(thread::spawn(move || {
            for j in 0..50 {
                let name = format!("file{}.txt", (i + j) % 10);
                if let Ok((inode, _)) = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new(&name)) {
                    if let Ok(handle) = fs.open(inode, libc::O_RDONLY as u32) {
                        let _ = fs.read(handle, 0, 100);
                        let _ = fs.release(handle);
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

/// Security regression: a name that is not a single safe path component must be
/// rejected at lookup, so the guest cannot obtain a nodeid outside the shared
/// root (which it could then read/write or DAX-map).
#[test]
fn lookup_rejects_path_traversal_names() {
    let (temp, fs) = setup_test_fs();
    for name in ["..", ".", "", "../etc/passwd", "/etc/passwd", "a/b"] {
        assert!(
            fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new(name))
                .is_err(),
            "unsafe FUSE name {name:?} must be rejected, not resolved"
        );
    }
    // A normal single component still resolves.
    std::fs::write(temp.path().join("normal.txt"), b"x").unwrap();
    fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("normal.txt"))
        .expect("a safe name must resolve normally");
}

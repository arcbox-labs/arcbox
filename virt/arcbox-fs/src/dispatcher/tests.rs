use std::mem::size_of;
use std::sync::Arc;

use tempfile::TempDir;

use crate::fuse::*;
use crate::passthrough::PassthroughFs;

use super::*;

fn setup_dispatcher() -> (TempDir, FuseDispatcher) {
    let temp = TempDir::new().expect("failed to create temp dir");
    let fs = Arc::new(PassthroughFs::new(temp.path()).expect("failed to create fs"));
    let dispatcher = FuseDispatcher::new(fs, DispatcherConfig::default());
    (temp, dispatcher)
}

fn make_header(opcode: FuseOpcode, nodeid: u64, body_len: usize) -> Vec<u8> {
    let header = FuseInHeader {
        len: (FuseInHeader::SIZE + body_len) as u32,
        opcode: opcode as u32,
        unique: 1,
        nodeid,
        uid: 0,
        gid: 0,
        pid: 0,
        padding: 0,
    };

    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const FuseInHeader as *const u8,
            FuseInHeader::SIZE,
        )
    };
    header_bytes.to_vec()
}

fn parse_response_header(response: &[u8]) -> FuseOutHeader {
    assert!(response.len() >= FuseOutHeader::SIZE);
    // SAFETY: FuseOutHeader may sit at an unaligned offset in the response buffer.
    unsafe { std::ptr::read_unaligned(response.as_ptr() as *const FuseOutHeader) }
}

#[test]
fn test_getattr_root() {
    let (_temp, dispatcher) = setup_dispatcher();

    let request = make_header(FuseOpcode::Getattr, 1, 0);
    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);

    assert_eq!(header.error, 0);
    assert!(response.len() > FuseOutHeader::SIZE);
}

#[test]
fn test_lookup_nonexistent() {
    let (_temp, dispatcher) = setup_dispatcher();

    let name = b"nonexistent\0";
    let mut request = make_header(FuseOpcode::Lookup, 1, name.len());
    request.extend_from_slice(name);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);

    assert_eq!(header.error, -libc::ENOENT);
}

#[test]
fn test_lookup_existing() {
    let (temp, dispatcher) = setup_dispatcher();

    // Create a file
    std::fs::write(temp.path().join("test.txt"), "hello").unwrap();

    let name = b"test.txt\0";
    let mut request = make_header(FuseOpcode::Lookup, 1, name.len());
    request.extend_from_slice(name);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);

    assert_eq!(header.error, 0);
}

#[test]
fn test_mkdir_and_rmdir() {
    let (_temp, dispatcher) = setup_dispatcher();

    // Mkdir
    let mkdir_in = FuseMkdirIn {
        mode: 0o755,
        umask: 0,
    };
    let name = b"testdir\0";

    let mut request = make_header(FuseOpcode::Mkdir, 1, size_of::<FuseMkdirIn>() + name.len());
    let mkdir_bytes = unsafe {
        std::slice::from_raw_parts(
            &mkdir_in as *const FuseMkdirIn as *const u8,
            size_of::<FuseMkdirIn>(),
        )
    };
    request.extend_from_slice(mkdir_bytes);
    request.extend_from_slice(name);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);

    // Rmdir
    let mut request = make_header(FuseOpcode::Rmdir, 1, name.len());
    request.extend_from_slice(name);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);
}

#[test]
fn test_open_read_write_release() {
    let (temp, dispatcher) = setup_dispatcher();

    // Create file
    std::fs::write(temp.path().join("test.txt"), "initial").unwrap();

    // Lookup to get inode
    let name = b"test.txt\0";
    let mut request = make_header(FuseOpcode::Lookup, 1, name.len());
    request.extend_from_slice(name);
    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);

    // Extract inode from entry response
    // SAFETY: FuseEntryOut may sit at an unaligned offset in the response buffer.
    let entry = unsafe {
        std::ptr::read_unaligned(
            (response.as_ptr() as *const u8).add(FuseOutHeader::SIZE) as *const FuseEntryOut
        )
    };
    let inode = entry.nodeid;

    // Open
    let open_in = FuseOpenIn {
        flags: libc::O_RDWR as u32,
        unused: 0,
    };
    let mut request = make_header(FuseOpcode::Open, inode, size_of::<FuseOpenIn>());
    let open_bytes = unsafe {
        std::slice::from_raw_parts(
            &open_in as *const FuseOpenIn as *const u8,
            size_of::<FuseOpenIn>(),
        )
    };
    request.extend_from_slice(open_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);

    // Extract file handle
    // SAFETY: FuseOpenOut may sit at an unaligned offset in the response buffer.
    let open_out = unsafe {
        std::ptr::read_unaligned(
            (response.as_ptr() as *const u8).add(FuseOutHeader::SIZE) as *const FuseOpenOut
        )
    };
    let fh = open_out.fh;

    // Read
    let read_in = FuseReadIn {
        fh,
        offset: 0,
        size: 100,
        read_flags: 0,
        lock_owner: 0,
        flags: 0,
        padding: 0,
    };
    let mut request = make_header(FuseOpcode::Read, inode, size_of::<FuseReadIn>());
    let read_bytes = unsafe {
        std::slice::from_raw_parts(
            &read_in as *const FuseReadIn as *const u8,
            size_of::<FuseReadIn>(),
        )
    };
    request.extend_from_slice(read_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);

    let data = &response[FuseOutHeader::SIZE..];
    assert_eq!(data, b"initial");

    // Release
    let release_in = FuseReleaseIn {
        fh,
        flags: 0,
        release_flags: 0,
        lock_owner: 0,
    };
    let mut request = make_header(FuseOpcode::Release, inode, size_of::<FuseReleaseIn>());
    let release_bytes = unsafe {
        std::slice::from_raw_parts(
            &release_in as *const FuseReleaseIn as *const u8,
            size_of::<FuseReleaseIn>(),
        )
    };
    request.extend_from_slice(release_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);
}

#[test]
fn test_statfs() {
    let (_temp, dispatcher) = setup_dispatcher();

    let request = make_header(FuseOpcode::Statfs, 1, 0);
    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);

    assert_eq!(header.error, 0);
    assert!(response.len() >= FuseOutHeader::SIZE + size_of::<FuseStatfsOut>());
}

#[test]
fn test_unknown_opcode() {
    let (_temp, dispatcher) = setup_dispatcher();

    let header = FuseInHeader {
        len: FuseInHeader::SIZE as u32,
        opcode: 9999, // Unknown opcode
        unique: 1,
        nodeid: 1,
        uid: 0,
        gid: 0,
        pid: 0,
        padding: 0,
    };

    let request = unsafe {
        std::slice::from_raw_parts(
            &header as *const FuseInHeader as *const u8,
            FuseInHeader::SIZE,
        )
    };

    let result = dispatcher.dispatch(request);
    assert!(result.is_err());
}

#[test]
fn test_unsupported_opcode() {
    let (_temp, dispatcher) = setup_dispatcher();

    // IOCTL is unsupported
    let request = make_header(FuseOpcode::Ioctl, 1, 0);
    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);

    assert_eq!(header.error, -libc::ENOSYS);
}

#[test]
fn test_opendir_readdir_releasedir() {
    let (temp, dispatcher) = setup_dispatcher();

    // Create some files
    std::fs::write(temp.path().join("file1.txt"), "").unwrap();
    std::fs::write(temp.path().join("file2.txt"), "").unwrap();

    // Opendir
    let open_in = FuseOpenIn {
        flags: 0,
        unused: 0,
    };
    let mut request = make_header(FuseOpcode::Opendir, 1, size_of::<FuseOpenIn>());
    let open_bytes = unsafe {
        std::slice::from_raw_parts(
            &open_in as *const FuseOpenIn as *const u8,
            size_of::<FuseOpenIn>(),
        )
    };
    request.extend_from_slice(open_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);

    // SAFETY: FuseOpenOut may sit at an unaligned offset in the response buffer.
    let open_out = unsafe {
        std::ptr::read_unaligned(
            (response.as_ptr() as *const u8).add(FuseOutHeader::SIZE) as *const FuseOpenOut
        )
    };
    let fh = open_out.fh;

    // Readdir
    let read_in = FuseReadIn {
        fh,
        offset: 0,
        size: 4096,
        read_flags: 0,
        lock_owner: 0,
        flags: 0,
        padding: 0,
    };
    let mut request = make_header(FuseOpcode::Readdir, 1, size_of::<FuseReadIn>());
    let read_bytes = unsafe {
        std::slice::from_raw_parts(
            &read_in as *const FuseReadIn as *const u8,
            size_of::<FuseReadIn>(),
        )
    };
    request.extend_from_slice(read_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);

    // Parse dirent entries and verify each entry's `off` field equals
    // `base_offset + i` where base_offset = read_in.offset + 1 = 1.
    // This pins the `base_offset + i` formula introduced in ABX-366.
    {
        let body = &response[FuseOutHeader::SIZE..];
        let base_offset: u64 = read_in.offset + 1; // matches dispatcher formula
        let mut pos = 0usize;
        let mut i = 0usize;
        while pos + size_of::<FuseDirent>() <= body.len() {
            // SAFETY: FuseDirent may sit at any alignment in the packed response body.
            let dirent =
                unsafe { std::ptr::read_unaligned(body[pos..].as_ptr() as *const FuseDirent) };
            assert_eq!(
                dirent.off,
                base_offset + i as u64,
                "dirent[{i}].off should be base_offset({base_offset}) + {i}"
            );
            let entry_size = FuseDirent::size(dirent.namelen as usize);
            pos += entry_size;
            i += 1;
        }
        assert!(i > 0, "should have parsed at least one dirent entry");
    }

    // Releasedir
    let release_in = FuseReleaseIn {
        fh,
        flags: 0,
        release_flags: 0,
        lock_owner: 0,
    };
    let mut request = make_header(FuseOpcode::Releasedir, 1, size_of::<FuseReleaseIn>());
    let release_bytes = unsafe {
        std::slice::from_raw_parts(
            &release_in as *const FuseReleaseIn as *const u8,
            size_of::<FuseReleaseIn>(),
        )
    };
    request.extend_from_slice(release_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);
}

#[test]
fn test_response_builder() {
    let mut builder = ResponseBuilder::new();

    // Test error response
    builder.write_error(123, libc::ENOENT);
    let response = builder.as_bytes();
    let header = parse_response_header(response);
    assert_eq!(header.unique, 123);
    assert_eq!(header.error, -libc::ENOENT);
    assert_eq!(header.len as usize, FuseOutHeader::SIZE);

    // Test empty response
    builder.write_empty(456);
    let response = builder.as_bytes();
    let header = parse_response_header(response);
    assert_eq!(header.unique, 456);
    assert_eq!(header.error, 0);
    assert_eq!(header.len as usize, FuseOutHeader::SIZE);

    // Test bytes response
    builder.write_bytes(789, b"hello");
    let response = builder.as_bytes();
    let header = parse_response_header(response);
    assert_eq!(header.unique, 789);
    assert_eq!(header.error, 0);
    assert_eq!(header.len as usize, FuseOutHeader::SIZE + 5);
    assert_eq!(&response[FuseOutHeader::SIZE..], b"hello");
}

#[test]
fn test_readdirplus() {
    let (temp, dispatcher) = setup_dispatcher();

    // Create files so the directory has known entries
    std::fs::write(temp.path().join("alpha.txt"), "aaa").unwrap();
    std::fs::write(temp.path().join("beta.txt"), "bb").unwrap();

    // Opendir on root inode
    let open_in = FuseOpenIn {
        flags: 0,
        unused: 0,
    };
    let mut request = make_header(FuseOpcode::Opendir, 1, size_of::<FuseOpenIn>());
    let open_bytes = unsafe {
        std::slice::from_raw_parts(
            &open_in as *const FuseOpenIn as *const u8,
            size_of::<FuseOpenIn>(),
        )
    };
    request.extend_from_slice(open_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);

    let open_out = unsafe {
        std::ptr::read_unaligned(
            (response.as_ptr() as *const u8).add(FuseOutHeader::SIZE) as *const FuseOpenOut
        )
    };
    let fh = open_out.fh;

    // Send READDIRPLUS request
    let read_in = FuseReadIn {
        fh,
        offset: 0,
        size: 8192, // Generous buffer
        read_flags: 0,
        lock_owner: 0,
        flags: 0,
        padding: 0,
    };
    let mut request = make_header(FuseOpcode::Readdirplus, 1, size_of::<FuseReadIn>());
    let read_bytes = unsafe {
        std::slice::from_raw_parts(
            &read_in as *const FuseReadIn as *const u8,
            size_of::<FuseReadIn>(),
        )
    };
    request.extend_from_slice(read_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0, "READDIRPLUS should succeed");

    // The response body should be non-empty (it contains entries for
    // at least ".", "..", "alpha.txt", "beta.txt").
    let body_len = response.len() - FuseOutHeader::SIZE;
    assert!(
        body_len > 0,
        "READDIRPLUS response should contain directory entries"
    );

    // Each READDIRPLUS entry starts with a FuseEntryOut followed by a
    // FuseDirent. Verify we can parse the first entry.
    let body = &response[FuseOutHeader::SIZE..];
    assert!(
        body.len() >= size_of::<FuseEntryOut>() + size_of::<FuseDirent>(),
        "Response should contain at least one full READDIRPLUS entry"
    );

    // Parse the first FuseEntryOut to verify it has valid timeouts
    let first_entry = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseEntryOut) };
    assert!(
        first_entry.nodeid > 0,
        "First entry should have a valid node ID"
    );
    assert!(
        first_entry.entry_valid > 0 || first_entry.attr_valid > 0,
        "First entry should have cache timeouts set"
    );

    // Releasedir
    let release_in = FuseReleaseIn {
        fh,
        flags: 0,
        release_flags: 0,
        lock_owner: 0,
    };
    let mut request = make_header(FuseOpcode::Releasedir, 1, size_of::<FuseReleaseIn>());
    let release_bytes = unsafe {
        std::slice::from_raw_parts(
            &release_in as *const FuseReleaseIn as *const u8,
            size_of::<FuseReleaseIn>(),
        )
    };
    request.extend_from_slice(release_bytes);

    let response = dispatcher.dispatch(&request).unwrap();
    let header = parse_response_header(&response);
    assert_eq!(header.error, 0);
}

// -----------------------------------------------------------------------
// #14 — sentinel-fh (FUSE_NO_FH) path in handle_setup_mapping
// -----------------------------------------------------------------------

#[test]
fn test_setup_mapping_sentinel_fh() {
    use crate::fuse::{FUSE_NO_FH, FuseSetupMappingIn};
    use std::sync::atomic::{AtomicBool, Ordering};

    // A mock DaxMapper that records whether setup_mapping was called.
    struct RecordingMapper {
        called: AtomicBool,
    }
    impl crate::DaxMapper for RecordingMapper {
        fn setup_mapping(
            &self,
            _host_fd: i32,
            _file_offset: u64,
            _window_offset: u64,
            _length: u64,
            _writable: bool,
        ) -> std::result::Result<(), i32> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn remove_mapping(
            &self,
            _window_offset: u64,
            _length: u64,
        ) -> std::result::Result<(), i32> {
            Ok(())
        }
    }

    let temp = tempfile::TempDir::new().unwrap();

    // Write a real file so the inode exists and open_inode_for_dax succeeds.
    std::fs::write(temp.path().join("exec_bin"), b"ELF_PAYLOAD").unwrap();

    let fs = Arc::new(PassthroughFs::new(temp.path()).unwrap());

    // Perform a LOOKUP so the dispatcher has the inode registered.
    let mapper = Arc::new(RecordingMapper {
        called: AtomicBool::new(false),
    });
    let mut dispatcher = FuseDispatcher::new(Arc::clone(&fs), DispatcherConfig::default());
    dispatcher.set_dax_mapper(Arc::clone(&mapper) as Arc<dyn crate::DaxMapper>);

    let name = b"exec_bin\0";
    let mut req = make_header(FuseOpcode::Lookup, 1, name.len());
    req.extend_from_slice(name);
    let resp = dispatcher.dispatch(&req).unwrap();
    let resp_hdr = parse_response_header(&resp);
    assert_eq!(resp_hdr.error, 0, "lookup must succeed");

    // SAFETY: FuseEntryOut may sit at an unaligned offset in the response buffer.
    let entry_out = unsafe {
        std::ptr::read_unaligned(
            (resp.as_ptr() as *const u8).add(FuseOutHeader::SIZE) as *const FuseEntryOut
        )
    };
    let inode = entry_out.nodeid;

    // Build FUSE_SETUPMAPPING with fh = FUSE_NO_FH (sentinel — no open fd).
    let mapping_in = FuseSetupMappingIn {
        fh: FUSE_NO_FH,
        foffset: 0,
        len: 4096,
        flags: 0, // read-only
        moffset: 0,
    };
    let mut req = make_header(
        FuseOpcode::SetupMapping,
        inode,
        size_of::<FuseSetupMappingIn>(),
    );
    let mapping_bytes = unsafe {
        std::slice::from_raw_parts(
            &mapping_in as *const FuseSetupMappingIn as *const u8,
            size_of::<FuseSetupMappingIn>(),
        )
    };
    req.extend_from_slice(mapping_bytes);

    let resp = dispatcher.dispatch(&req).unwrap();
    let resp_hdr = parse_response_header(&resp);

    // 1. Response error must be 0 — not ENOSYS or EBADF.
    assert_eq!(
        resp_hdr.error, 0,
        "SETUPMAPPING with FUSE_NO_FH sentinel should succeed (got errno {})",
        -resp_hdr.error
    );

    // 2. The mock setup_mapping must have been called exactly once.
    assert!(
        mapper.called.load(Ordering::SeqCst),
        "DaxMapper::setup_mapping should have been called via the sentinel-fh path"
    );
}

// -----------------------------------------------------------------------
// #15 — DaxFsExt::open_inode_for_dax (positive + TOCTOU negative)
// -----------------------------------------------------------------------

#[test]
fn test_dax_fs_ext_open_inode_for_dax_reads_content() {
    use crate::dispatcher::DaxFsExt;
    use std::io::Read;

    let temp = tempfile::TempDir::new().unwrap();
    std::fs::write(temp.path().join("data.bin"), b"hello dax").unwrap();

    let fs = PassthroughFs::new(temp.path()).unwrap();

    // Register the inode via lookup.
    let name = std::ffi::OsStr::new("data.bin");
    let (inode, _attr) = fs.lookup(1, name).unwrap();

    // (a) The returned file must be readable and contain the written content.
    let mut file = DaxFsExt::open_inode_for_dax(&fs, inode, false).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    assert_eq!(
        buf, b"hello dax",
        "open_inode_for_dax should expose file content"
    );
}

#[test]
fn test_dax_fs_ext_open_inode_for_dax_toctou_rename_detected() {
    use crate::dispatcher::DaxFsExt;

    let temp = tempfile::TempDir::new().unwrap();
    std::fs::write(temp.path().join("original.bin"), b"orig").unwrap();
    std::fs::write(temp.path().join("replacement.bin"), b"evil").unwrap();

    let fs = PassthroughFs::new(temp.path()).unwrap();

    // Register original.bin so the inode table maps inode → "original.bin".
    let name = std::ffi::OsStr::new("original.bin");
    let (inode, _attr) = fs.lookup(1, name).unwrap();

    // Simulate a TOCTOU swap: rename replacement.bin → original.bin so
    // the path now points to a different file (different kernel st_ino).
    std::fs::rename(
        temp.path().join("replacement.bin"),
        temp.path().join("original.bin"),
    )
    .unwrap();

    // open_inode_for_dax must detect the st_ino mismatch and return EIO.
    let result = DaxFsExt::open_inode_for_dax(&fs, inode, false);
    let err = result.expect_err("should fail with EIO after TOCTOU swap");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EIO),
        "expected EIO for TOCTOU-detected rename, got: {err}"
    );
}

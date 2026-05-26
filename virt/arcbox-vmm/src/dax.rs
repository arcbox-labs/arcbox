//! VirtioFS DAX (Direct Access) mapper implementation.
//!
//! Maps host file pages into the guest's DAX window IPA region using
//! Hypervisor.framework's `hv_vm_map` / `hv_vm_unmap` global APIs.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Computes DAX window base IPA — placed immediately after guest RAM.
/// Must be above RAM so `devm_memremap_pages` can register it as ZONE_DEVICE.
pub fn dax_window_base(ram_base: u64, ram_size: u64) -> u64 {
    // Page-align to 2MB boundary (huge page) for optimal TLB usage.
    let after_ram = ram_base + ram_size;
    (after_ram + 0x1F_FFFF) & !0x1F_FFFF
}

/// DAX window size per VirtioFS share (128 MB each).
pub const DAX_WINDOW_PER_SHARE: u64 = 128 * 1024 * 1024;

/// Total DAX window size for a given number of VirtioFS shares.
pub fn dax_window_total(num_shares: usize) -> u64 {
    num_shares.max(1) as u64 * DAX_WINDOW_PER_SHARE
}

/// Selects the `mmap(2)` sharing flags for a DAX mapping.
///
/// Writable shares use `MAP_SHARED` so guest writes propagate to the host
/// file. Read-only shares use `MAP_PRIVATE` (COW) — `hv_vm_map` still
/// requires a writable host VA on Apple Silicon, and COW ensures that any
/// speculative writes never reach the underlying file.
/// `MAP_ANON` is not set here; the fd-backed path is always used for DAX.
fn mmap_flags_for(writable: bool) -> i32 {
    if writable {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    }
}

/// A single active DAX mapping.
struct DaxMapping {
    host_ptr: *mut u8,
    guest_ipa: u64,
    length: usize,
}

// SAFETY: host_ptr is from mmap, valid for mapping lifetime.
unsafe impl Send for DaxMapping {}

/// Observability counters for DAX activity.
///
/// Updated from the hot path (setup_mapping / remove_mapping) with
/// atomic-relaxed writes — suitable for assertions in integration
/// tests and for lightweight telemetry.
#[derive(Debug, Default, Clone, Copy)]
pub struct DaxStats {
    /// Total successful `setup_mapping` calls since mapper creation.
    pub setup_count: u64,
    /// Sum of `length` across all successful `setup_mapping` calls (bytes).
    pub setup_bytes: u64,
    /// Total successful `remove_mapping` calls since mapper creation.
    pub remove_count: u64,
}

/// DAX mapper backed by Hypervisor.framework global hv_vm_map/unmap.
pub struct HvDaxMapper {
    mappings: Mutex<BTreeMap<u64, DaxMapping>>,
    /// Base IPA of the DAX window (computed from RAM layout).
    base_ipa: u64,
    /// Total DAX window size — mappings must stay within [0, window_size).
    window_size: u64,
    /// Host page size in bytes, queried once at construction.
    ///
    /// Used as the alignment mask for `setup_mapping`. Matches the
    /// `sysconf(_SC_PAGESIZE)` call in `arcbox-fs/src/dispatcher.rs` —
    /// both sides must agree on granularity or alignment checks diverge.
    page_size: u64,
    /// Set to `true` by `drain_all` so `Drop` skips the FFI calls.
    drained: AtomicBool,
    /// Successful setup count (observability).
    setup_count: AtomicU64,
    /// Successful setup bytes (observability).
    setup_bytes: AtomicU64,
    /// Successful remove count (observability).
    remove_count: AtomicU64,
}

impl HvDaxMapper {
    pub fn new(base_ipa: u64, window_size: u64) -> Self {
        // Query the host page size so alignment checks stay in sync with the
        // dispatcher (arcbox-fs/src/dispatcher.rs uses the same sysconf call).
        let page_size = {
            // SAFETY: `_SC_PAGESIZE` is a valid sysconf key; negative return
            // means unsupported, which we treat as the safe 4 KiB fallback.
            let r = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if r > 0 { r as u64 } else { 4096 }
        };
        Self {
            mappings: Mutex::new(BTreeMap::new()),
            base_ipa,
            window_size,
            page_size,
            drained: AtomicBool::new(false),
            setup_count: AtomicU64::new(0),
            setup_bytes: AtomicU64::new(0),
            remove_count: AtomicU64::new(0),
        }
    }

    /// Returns a snapshot of the observability counters. Cheap — reads
    /// three atomic-relaxed loads, allocates nothing.
    pub fn stats(&self) -> DaxStats {
        DaxStats {
            setup_count: self.setup_count.load(Ordering::Relaxed),
            setup_bytes: self.setup_bytes.load(Ordering::Relaxed),
            remove_count: self.remove_count.load(Ordering::Relaxed),
        }
    }

    /// Drains all active DAX mappings, calling `hv_vm_unmap` + `munmap` on
    /// each entry, then clears the internal map.
    ///
    /// Must be called **before** `hv_vm_destroy` so every `hv_vm_unmap` runs
    /// against a live VM. After `drain_all`, `Drop` becomes a no-op —
    /// idempotent and safe to call twice.
    pub fn drain_all(&self) {
        let mut mappings = self
            .mappings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for mapping in mappings.values() {
            // SAFETY: `mapping.guest_ipa` and `mapping.length` come from a
            // prior successful `hv_vm_map` call, and `hv_vm_destroy` has not
            // yet been called at this point (drain_all is invoked before that).
            let ret = unsafe { arcbox_hv::ffi::hv_vm_unmap(mapping.guest_ipa, mapping.length) };
            if ret != 0 {
                tracing::warn!(
                    "DAX drain_all: hv_vm_unmap ipa={:#x} len={} failed: ret={ret}",
                    mapping.guest_ipa,
                    mapping.length,
                );
            }
            // SAFETY: `mapping.host_ptr` is the address returned by the
            // original `mmap` call for this entry; `mapping.length` is the
            // same length passed to that `mmap`. The mapping is still live —
            // nothing else has called `munmap` on this range.
            let munmap_ret = unsafe { libc::munmap(mapping.host_ptr.cast(), mapping.length) };
            if munmap_ret != 0 {
                let errno = std::io::Error::last_os_error();
                tracing::warn!(
                    "DAX drain_all: munmap failed for ipa={:#x} len={}: {errno}",
                    mapping.guest_ipa,
                    mapping.length,
                );
            }
        }
        mappings.clear();

        // Mark drained only after the cleanup loop and `mappings.clear()`
        // both complete. Setting it earlier is unsafe: if a panic unwinds
        // through the loop, `Drop` would see `drained=true` and skip the
        // still-live entries in the map, leaking their host VA ranges.
        // Individual `hv_vm_unmap` / `munmap` failures inside the loop are
        // logged but not retried — `drained=true` after the loop means
        // "cleanup was attempted for every entry," not "every entry was
        // successfully freed." Release-stored; the matching `Acquire` load
        // in `Drop` establishes happens-before with the cleanup above.
        self.drained.store(true, Ordering::Release);
    }
}

impl arcbox_fs::DaxMapper for HvDaxMapper {
    fn setup_mapping(
        &self,
        host_fd: i32,
        file_offset: u64,
        window_offset: u64,
        length: u64,
        writable: bool,
    ) -> Result<(), i32> {
        let page_mask = self.page_size - 1;
        if (file_offset | window_offset | length) & page_mask != 0 {
            return Err(libc::EINVAL);
        }
        if length == 0 {
            return Err(libc::EINVAL);
        }

        // Bounds check: mapping must fit within the DAX window.
        let end = window_offset.checked_add(length).ok_or(libc::EINVAL)?;
        if end > self.window_size {
            tracing::warn!(
                "DAX setup_mapping out of bounds: offset={:#x} len={:#x} window_size={:#x}",
                window_offset,
                length,
                self.window_size,
            );
            return Err(libc::EINVAL);
        }

        // Hold the lock across overlap check, mmap, hv_vm_map, and insertion
        // to prevent TOCTOU races between concurrent setup_mapping calls.
        // mmap and hv_vm_map are sub-microsecond, so holding the mutex is fine.
        let mut mappings = self
            .mappings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Overlap check: no existing mapping may intersect [window_offset, end).
        for (&existing_offset, existing) in &*mappings {
            let existing_end = existing_offset + existing.length as u64;
            if window_offset < existing_end && end > existing_offset {
                tracing::warn!(
                    "DAX setup_mapping overlap: new [{:#x}..{:#x}) vs existing [{:#x}..{:#x})",
                    window_offset,
                    end,
                    existing_offset,
                    existing_end,
                );
                return Err(libc::EEXIST);
            }
        }

        // Apple Silicon's `hv_vm_map` requires the host virtual address
        // backing to be writable even when the stage-2 mapping is installed
        // read-only. We always open the host mmap with PROT_READ|PROT_WRITE
        // so the kernel accepts the mapping, and then use `MAP_PRIVATE` to
        // ensure writes from the guest (if any) stay local as
        // copy-on-write and never hit the host file. The flags we pass to
        // `hv_vm_map` still reflect the requested guest permissions.
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let mmap_flags = mmap_flags_for(writable);

        // SAFETY: `host_fd` is a valid open fd passed in by the FUSE dispatcher.
        // `length` is non-zero and page-aligned (checked above). `MAP_PRIVATE` +
        // `PROT_WRITE` is valid on an `O_RDONLY` fd (COW semantics). The return
        // value is validated against `MAP_FAILED` immediately below.
        let host_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length as usize,
                prot,
                mmap_flags,
                host_fd,
                #[allow(clippy::cast_possible_wrap)]
                {
                    file_offset as libc::off_t
                },
            )
        };
        if host_ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }

        let guest_ipa = self.base_ipa + window_offset;
        // The FUSE SETUPMAPPING protocol only carries READ / WRITE flags,
        // not EXECUTE. But the guest kernel routinely exec's binaries
        // directly out of DAX (that is the whole point of the fast path),
        // so every readable DAX mapping must be installed as stage-2
        // executable too — otherwise the first instruction fetch through
        // the mapping faults with a stage-2 InstructionAbort and the guest
        // process dies before it can run. This matches how qemu-virtiofsd
        // grants `PROT_EXEC` alongside `PROT_READ` on the guest VA.
        let perm = if writable {
            arcbox_hv::MemoryPermission::READ
                | arcbox_hv::MemoryPermission::WRITE
                | arcbox_hv::MemoryPermission::EXEC
        } else {
            arcbox_hv::MemoryPermission::READ | arcbox_hv::MemoryPermission::EXEC
        };

        // Map the host file region into the guest IPA. The DAX window is
        // reserved but not pre-mapped, so `hv_vm_map` installs a fresh
        // stage-2 mapping. If a previous SETUPMAPPING occupied this slot
        // without a matching REMOVEMAPPING, the call will fail — that is a
        // guest-side bug we surface as EEXIST.
        let ret = unsafe {
            arcbox_hv::ffi::hv_vm_map(host_ptr.cast(), guest_ipa, length as usize, perm.bits())
        };
        if ret != 0 {
            tracing::warn!(
                "DAX hv_vm_map failed: ret={:#x} host_ptr={host_ptr:p} ipa={guest_ipa:#x} len={length:#x} perm={:#x}",
                ret as u32,
                perm.bits(),
            );
            // SAFETY: `host_ptr` was just returned by the `mmap` call above
            // and has not yet been registered anywhere, so this is the only
            // reference to it.
            unsafe { libc::munmap(host_ptr, length as usize) };
            // EIO is the correct errno for a framework-level failure here.
            // EFAULT would imply the *caller* passed a bad pointer, which is
            // misleading — the address was valid from our mmap; the framework
            // rejected the mapping for its own reasons (e.g. HV_NO_RESOURCES).
            return Err(libc::EIO);
        }

        mappings.insert(
            window_offset,
            DaxMapping {
                host_ptr: host_ptr.cast(),
                guest_ipa,
                length: length as usize,
            },
        );

        self.setup_count.fetch_add(1, Ordering::Relaxed);
        self.setup_bytes.fetch_add(length, Ordering::Relaxed);

        tracing::debug!(
            "DAX setup: window_offset={:#x} len={:#x} ipa={:#x}",
            window_offset,
            length,
            guest_ipa,
        );
        Ok(())
    }

    fn remove_mapping(&self, window_offset: u64, length: u64) -> Result<(), i32> {
        let mut mappings = self
            .mappings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mapping) = mappings.remove(&window_offset) else {
            return Err(libc::ENOENT);
        };

        // Validate that the requested length matches the stored mapping.
        // Partial unmaps are not supported — return EINVAL and restore.
        if length as usize != mapping.length {
            tracing::warn!(
                "DAX remove_mapping length mismatch: requested={:#x} stored={:#x}",
                length,
                mapping.length,
            );
            mappings.insert(window_offset, mapping);
            return Err(libc::EINVAL);
        }

        // Unmap from guest IPA. If this fails the VM is in a bad state, so
        // return an error rather than silently proceeding to munmap — a
        // dangling stage-2 mapping is worse than a leaked host VA.
        // SAFETY: `mapping.guest_ipa` and `mapping.length` come from a prior
        // successful `hv_vm_map`; the VM is alive during normal operation.
        let ret = unsafe { arcbox_hv::ffi::hv_vm_unmap(mapping.guest_ipa, mapping.length) };
        if ret != 0 {
            tracing::warn!(
                "DAX hv_vm_unmap failed: ret={ret} ipa={:#x} len={}; aborting remove",
                mapping.guest_ipa,
                mapping.length,
            );
            // Restore the entry so the guest can retry.
            mappings.insert(window_offset, mapping);
            return Err(libc::EIO);
        }

        // SAFETY: `mapping.host_ptr` was returned by a prior `mmap` for this
        // entry and is still live — `hv_vm_unmap` just removed the stage-2
        // reference. `mapping.length` matches the original mmap length.
        let munmap_ret = unsafe { libc::munmap(mapping.host_ptr.cast(), mapping.length) };
        if munmap_ret != 0 {
            // munmap failure after a successful hv_vm_unmap is an accounting
            // concern only — the stage-2 mapping is already gone. Log and
            // continue rather than returning an error to the guest.
            let errno = std::io::Error::last_os_error();
            tracing::warn!(
                "DAX munmap failed for ipa={:#x} len={}: {errno}",
                mapping.guest_ipa,
                mapping.length,
            );
        }

        self.remove_count.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            "DAX remove: window_offset={:#x} len={:#x}",
            window_offset,
            length,
        );
        Ok(())
    }
}

impl Drop for HvDaxMapper {
    fn drop(&mut self) {
        // `drain_all` was called by stop_darwin_hv before hv_vm_destroy,
        // so all mappings are already gone. Skip FFI to avoid calling
        // hv_vm_unmap against a destroyed VM (UB per Apple's doc).
        if self.drained.load(Ordering::Acquire) {
            return;
        }

        // Panic path: the VM was not stopped cleanly. Attempt cleanup but
        // acknowledge the UB risk — hv_vm_destroy may have already run.
        tracing::warn!(
            "HvDaxMapper dropped without drain_all — attempting emergency \
             cleanup; hv_vm_unmap may be called on a destroyed VM (UB risk)"
        );
        let mappings = self
            .mappings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for mapping in mappings.values() {
            // SAFETY: We attempt cleanup on the panic path knowing that
            // `hv_vm_destroy` may have already run. The UB risk is
            // acknowledged above; this is best-effort to avoid leaked mmaps.
            unsafe {
                arcbox_hv::ffi::hv_vm_unmap(mapping.guest_ipa, mapping.length);
                libc::munmap(mapping.host_ptr.cast(), mapping.length);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_start_zero() {
        let m = HvDaxMapper::new(0x8000_0000, 128 * 1024 * 1024);
        let s = m.stats();
        assert_eq!(s.setup_count, 0);
        assert_eq!(s.setup_bytes, 0);
        assert_eq!(s.remove_count, 0);
    }

    #[test]
    fn stats_reflect_fetch_add() {
        let m = HvDaxMapper::new(0x8000_0000, 128 * 1024 * 1024);
        // Simulate what the hot path does on a successful setup.
        m.setup_count.fetch_add(3, Ordering::Relaxed);
        m.setup_bytes.fetch_add(4096 * 3, Ordering::Relaxed);
        m.remove_count.fetch_add(1, Ordering::Relaxed);
        let s = m.stats();
        assert_eq!(s.setup_count, 3);
        assert_eq!(s.setup_bytes, 4096 * 3);
        assert_eq!(s.remove_count, 1);
    }

    /// Verifies that `mmap_flags_for` selects the correct sharing semantics.
    /// MAP_SHARED for writable (writes must reach the host file),
    /// MAP_PRIVATE for read-only (COW keeps writes from touching the file).
    #[test]
    fn mmap_flags_writable_vs_readonly() {
        assert_eq!(
            mmap_flags_for(true),
            libc::MAP_SHARED,
            "writable mapping must use MAP_SHARED"
        );
        assert_eq!(
            mmap_flags_for(false),
            libc::MAP_PRIVATE,
            "read-only mapping must use MAP_PRIVATE (COW)"
        );
    }
}

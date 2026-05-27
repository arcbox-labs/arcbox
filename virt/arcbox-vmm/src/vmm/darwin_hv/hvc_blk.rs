//! HVC fast-path block I/O.
//!
//! The guest's ArcBox block driver issues an HVC with a vendor-specific
//! SMCCC function ID (0xC200_XXXX range) instead of walking a virtqueue.
//! The hypervisor translates the buffer GPA to a host pointer and performs
//! a synchronous pread/pwrite/fsync directly against the backing file.
//! Returns bytes transferred in X0, or a negative errno on failure.

use arcbox_hv::reg::{HV_REG_X1 as X1, HV_REG_X2 as X2, HV_REG_X3 as X3, HV_REG_X4 as X4};

/// HVC probe: returns number of block devices available for fast path.
/// No arguments. Returns X0 = num_devices.
pub const ARCBOX_HVC_PROBE: u64 = 0xC200_0000;

/// HVC block read. X1=dev_idx, X2=sector, X3=buffer_gpa, X4=byte_len.
/// Returns X0 = bytes read (>0) or negative errno.
pub const ARCBOX_HVC_BLK_READ: u64 = 0xC200_0001;

/// HVC block write. X1=dev_idx, X2=sector, X3=buffer_gpa, X4=byte_len.
/// Returns X0 = bytes written (>0) or negative errno.
pub const ARCBOX_HVC_BLK_WRITE: u64 = 0xC200_0002;

/// HVC block flush (fsync). X1=dev_idx.
/// Returns X0 = 0 on success or negative errno.
pub const ARCBOX_HVC_BLK_FLUSH: u64 = 0xC200_0003;

/// HVC block read or write.
/// X1=device_idx, X2=sector, X3=buffer_gpa, X4=byte_length.
/// `is_write`: false=pread, true=pwrite.
pub fn handle_hvc_blk_io(
    vcpu: &arcbox_hv::HvVcpu,
    hvc_blk_fds: &[(i32, u32)],
    device_manager: &crate::device::DeviceManager,
    is_write: bool,
) -> u64 {
    let Ok(device_idx) = vcpu.get_reg(X1) else {
        return (-libc::EINVAL as i64) as u64;
    };
    let Ok(sector) = vcpu.get_reg(X2) else {
        return (-libc::EINVAL as i64) as u64;
    };
    let Ok(buffer_gpa) = vcpu.get_reg(X3) else {
        return (-libc::EINVAL as i64) as u64;
    };
    let Ok(byte_len) = vcpu.get_reg(X4) else {
        return (-libc::EINVAL as i64) as u64;
    };

    let byte_len = byte_len as usize;
    if byte_len == 0 {
        return (-libc::EINVAL as i64) as u64;
    }

    let Some(&(raw_fd, blk_size)) = hvc_blk_fds.get(device_idx as usize) else {
        return (-libc::ENODEV as i64) as u64;
    };

    let Some(ram_base) = device_manager.guest_ram_base_ptr() else {
        return (-libc::EFAULT as i64) as u64;
    };
    let gpa_base = device_manager.guest_ram_gpa() as usize;
    let ram_size = device_manager.guest_ram_size();
    let gpa = buffer_gpa as usize;

    if gpa < gpa_base
        || gpa
            .checked_add(byte_len)
            .is_none_or(|end| end > gpa_base + ram_size)
    {
        return (-libc::EFAULT as i64) as u64;
    }

    // SAFETY: The bounds check above guarantees `gpa - gpa_base + byte_len`
    // is within the allocation pointed to by `ram_base`. `ram_base` is the
    // live host mapping tracked by `DeviceManager` for the VM's lifetime.
    let host_ptr = unsafe { ram_base.add(gpa - gpa_base) };

    let Some(byte_offset) = sector.checked_mul(u64::from(blk_size)) else {
        return (-libc::EINVAL as i64) as u64;
    };
    #[allow(clippy::cast_possible_wrap)]
    let offset = byte_offset as libc::off_t;

    // SAFETY: `host_ptr` is valid for `byte_len` bytes (bounds-checked
    // above) and `raw_fd` is an open fd from `hvc_blk_fds` (owned by the
    // VMM). pread/pwrite take an exclusive borrow for the call duration;
    // the guest vCPU that triggered this HVC is parked, so no aliasing.
    let n = if is_write {
        unsafe { libc::pwrite(raw_fd, host_ptr.cast(), byte_len, offset) }
    } else {
        unsafe { libc::pread(raw_fd, host_ptr.cast(), byte_len, offset) }
    };
    if n < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return (-errno as i64) as u64;
    }
    n as u64
}

/// HVC block flush (fsync). X1=device_idx.
pub fn handle_hvc_blk_flush(vcpu: &arcbox_hv::HvVcpu, hvc_blk_fds: &[(i32, u32)]) -> u64 {
    let Ok(device_idx) = vcpu.get_reg(X1) else {
        return (-libc::EINVAL as i64) as u64;
    };
    let Some(&(raw_fd, _)) = hvc_blk_fds.get(device_idx as usize) else {
        return (-libc::ENODEV as i64) as u64;
    };
    // SAFETY: `raw_fd` is an open fd from `hvc_blk_fds` owned by the VMM;
    // fsync is side-effect-only on the file descriptor.
    let ret = unsafe { libc::fsync(raw_fd) };
    if ret < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return (-errno as i64) as u64;
    }
    0
}

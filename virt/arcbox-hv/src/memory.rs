//! Guest physical memory permission flags.

/// Permission flags for guest physical address (IPA) memory mappings.
///
/// These map directly to `HV_MEMORY_READ`, `HV_MEMORY_WRITE`, and
/// `HV_MEMORY_EXEC` from Hypervisor.framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPermission(u64);

impl MemoryPermission {
    /// Allow guest reads.
    pub const READ: Self = Self(1 << 0);
    /// Allow guest writes.
    pub const WRITE: Self = Self(1 << 1);
    /// Allow guest instruction fetches.
    pub const EXEC: Self = Self(1 << 2);
    /// Read + Write (no execute).
    pub const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);
    /// Read + Write + Execute.
    pub const ALL: Self = Self(Self::READ.0 | Self::WRITE.0 | Self::EXEC.0);

    /// Return the raw bitmask for passing to FFI.
    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` if `self` contains all bits in `other`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for MemoryPermission {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for MemoryPermission {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_is_union() {
        let rw = MemoryPermission::READ | MemoryPermission::WRITE;
        assert_eq!(rw, MemoryPermission::READ_WRITE);
    }

    #[test]
    fn all_contains_individual_flags() {
        assert!(MemoryPermission::ALL.contains(MemoryPermission::READ));
        assert!(MemoryPermission::ALL.contains(MemoryPermission::WRITE));
        assert!(MemoryPermission::ALL.contains(MemoryPermission::EXEC));
    }

    #[test]
    fn bits_match_framework_constants() {
        assert_eq!(MemoryPermission::READ.bits(), 1);
        assert_eq!(MemoryPermission::WRITE.bits(), 2);
        assert_eq!(MemoryPermission::EXEC.bits(), 4);
    }

    #[test]
    fn read_does_not_contain_write() {
        assert!(!MemoryPermission::READ.contains(MemoryPermission::WRITE));
    }
}

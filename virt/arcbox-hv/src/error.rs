use crate::ffi::hv_return_t;

/// Status codes returned by Hypervisor.framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HvError {
    #[error("generic hypervisor error")]
    Error,
    #[error("resource is busy")]
    Busy,
    #[error("bad argument")]
    BadArgument,
    #[error("illegal guest state")]
    IllegalGuestState,
    #[error("no resources available")]
    NoResources,
    #[error("no device found")]
    NoDevice,
    #[error("permission denied")]
    Denied,
    #[error("operation not supported")]
    Unsupported,
    #[error("unknown hypervisor error (0x{0:08x})")]
    Unknown(u32),
}

/// Convenience alias used throughout the crate.
pub type HvResult<T> = Result<T, HvError>;

// Known status codes from <Hypervisor/hv_error.h>.
const HV_SUCCESS: hv_return_t = 0;
const HV_ERROR: hv_return_t = 0xfae9_4001_u32.cast_signed();
const HV_BUSY: hv_return_t = 0xfae9_4002_u32.cast_signed();
const HV_BAD_ARGUMENT: hv_return_t = 0xfae9_4003_u32.cast_signed();
const HV_ILLEGAL_GUEST_STATE: hv_return_t = 0xfae9_4004_u32.cast_signed();
const HV_NO_RESOURCES: hv_return_t = 0xfae9_4005_u32.cast_signed();
const HV_NO_DEVICE: hv_return_t = 0xfae9_4006_u32.cast_signed();
const HV_DENIED: hv_return_t = 0xfae9_4007_u32.cast_signed();
const HV_UNSUPPORTED: hv_return_t = 0xfae9_400f_u32.cast_signed();

/// Convert a raw `hv_return_t` into `HvResult<()>`.
///
/// Returns `Ok(())` for `HV_SUCCESS`, otherwise maps the code to the
/// appropriate [`HvError`] variant.
pub fn check(status: hv_return_t) -> HvResult<()> {
    match status {
        HV_SUCCESS => Ok(()),
        HV_ERROR => Err(HvError::Error),
        HV_BUSY => Err(HvError::Busy),
        HV_BAD_ARGUMENT => Err(HvError::BadArgument),
        HV_ILLEGAL_GUEST_STATE => Err(HvError::IllegalGuestState),
        HV_NO_RESOURCES => Err(HvError::NoResources),
        HV_NO_DEVICE => Err(HvError::NoDevice),
        HV_DENIED => Err(HvError::Denied),
        HV_UNSUPPORTED => Err(HvError::Unsupported),
        other => Err(HvError::Unknown(other as u32)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_maps_to_ok() {
        assert!(check(HV_SUCCESS).is_ok());
    }

    #[test]
    fn known_codes_map_correctly() {
        assert_eq!(check(HV_ERROR), Err(HvError::Error));
        assert_eq!(check(HV_BUSY), Err(HvError::Busy));
        assert_eq!(check(HV_BAD_ARGUMENT), Err(HvError::BadArgument));
        assert_eq!(
            check(HV_ILLEGAL_GUEST_STATE),
            Err(HvError::IllegalGuestState)
        );
        assert_eq!(check(HV_NO_RESOURCES), Err(HvError::NoResources));
        assert_eq!(check(HV_NO_DEVICE), Err(HvError::NoDevice));
        assert_eq!(check(HV_DENIED), Err(HvError::Denied));
        assert_eq!(check(HV_UNSUPPORTED), Err(HvError::Unsupported));
    }

    #[test]
    fn unknown_code_preserved() {
        let code = 0xdead_beef_u32.cast_signed();
        assert_eq!(check(code), Err(HvError::Unknown(0xdead_beef)));
    }

    #[test]
    fn error_display() {
        assert_eq!(HvError::Error.to_string(), "generic hypervisor error");
        assert_eq!(
            HvError::Unknown(0x1234).to_string(),
            "unknown hypervisor error (0x00001234)"
        );
    }
}

//! VM exit reason parsing for ARM64 Hypervisor.framework.
//!
//! After each `hv_vcpu_run` call, the framework populates an exit info
//! structure. This module converts the raw fields into a typed [`VcpuExit`]
//! enum that VMM code can match on.

use crate::ffi;

// ARM64 Exception Class (EC) values from the syndrome register.
const EC_WFI_WFE: u8 = 0x01;
const EC_HVC: u8 = 0x16;
const EC_SMC: u8 = 0x17;
const EC_SYS_REG: u8 = 0x18;
const EC_INSN_ABORT_LOWER: u8 = 0x20;
const EC_INSN_ABORT_SAME: u8 = 0x21;
const EC_DATA_ABORT_LOWER: u8 = 0x24;
const EC_DATA_ABORT_SAME: u8 = 0x25;
const EC_SOFTWARE_BREAKPOINT: u8 = 0x3c;

/// High-level representation of a vCPU exit.
#[derive(Debug)]
pub enum VcpuExit {
    /// The vCPU run was canceled (e.g. by `hv_vcpus_exit`).
    Canceled,
    /// An exception was taken that the hypervisor cannot handle.
    Exception {
        class: ExceptionClass,
        syndrome: u64,
    },
    /// The virtual timer fired.
    VtimerActivated,
    /// An exit reason the framework returned that we do not recognise.
    Unknown(u32),
}

/// Decoded ARM64 exception class (EC field of ESR_EL2).
#[derive(Debug)]
pub enum ExceptionClass {
    /// Data abort — the guest accessed an unmapped IPA (MMIO).
    DataAbort(MmioInfo),
    /// Instruction abort — the guest tried to execute from an unmapped/faulting IPA.
    InstructionAbort {
        /// Guest physical address of the faulting instruction.
        address: u64,
        /// Instruction Fault Status Code (IFSC, bits [5:0]).
        fault_code: u8,
    },
    /// Software breakpoint (BRK #imm16).
    SoftwareBreakpoint(u16),
    /// WFI / WFE — the guest is idle.
    WaitForInterrupt,
    /// HVC #imm16 — hypercall from the guest.
    HypercallHvc(u16),
    /// SMC #imm16 — secure monitor call.
    SmcCall(u16),
    /// MSR/MRS trap — the guest accessed a system register that we trap.
    SystemRegister {
        op0: u8,
        op1: u8,
        crn: u8,
        crm: u8,
        op2: u8,
        /// `true` for MSR (write), `false` for MRS (read).
        is_write: bool,
        /// The general-purpose register (Xt) involved.
        rt: u8,
    },
    /// An EC value we do not explicitly handle.
    Other(u8),
}

/// Describes a guest MMIO access decoded from a data-abort syndrome.
#[derive(Debug)]
pub struct MmioInfo {
    /// Guest physical address that was accessed.
    pub address: u64,
    /// `true` if the guest was writing, `false` if reading.
    pub is_write: bool,
    /// Width of the access: 1, 2, 4, or 8 bytes.
    pub access_size: u8,
    /// The ARM general-purpose register (Xt) used.
    pub register: u8,
    /// For writes, always `0` — the syndrome does not carry the written data.
    /// The VMM must call `HvVcpu::get_reg(self.register)` to read the value
    /// the guest intended to write. For reads, the VMM writes the emulated
    /// value back via `HvVcpu::set_reg(self.register, value)`.
    pub value: u64,
    /// Whether the loaded value should be sign-extended.
    pub sign_extend: bool,
}

/// Parse a raw [`ffi::HvVcpuExitInfo`] into a typed [`VcpuExit`].
pub fn parse_exit(info: &ffi::HvVcpuExitInfo) -> VcpuExit {
    match info.reason {
        ffi::HV_EXIT_REASON_CANCELED => VcpuExit::Canceled,
        ffi::HV_EXIT_REASON_EXCEPTION => {
            let syndrome = info.exception.syndrome;
            let class = parse_exception(syndrome, &info.exception);
            VcpuExit::Exception { class, syndrome }
        }
        ffi::HV_EXIT_REASON_VTIMER_ACTIVATED => VcpuExit::VtimerActivated,
        other => VcpuExit::Unknown(other),
    }
}

/// Decode the exception class from the ESR syndrome value.
fn parse_exception(syndrome: u64, exc: &ffi::HvVcpuExitException) -> ExceptionClass {
    let ec = ((syndrome >> 26) & 0x3f) as u8;

    match ec {
        EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME => {
            let is_write = ((syndrome >> 6) & 1) != 0;
            let sas = ((syndrome >> 22) & 3) as u8;
            let access_size = 1u8 << sas;
            let register = ((syndrome >> 16) & 0x1f) as u8;
            let sign_extend = ((syndrome >> 21) & 1) != 0;

            ExceptionClass::DataAbort(MmioInfo {
                address: exc.physical_address,
                is_write,
                access_size,
                register,
                value: 0,
                sign_extend,
            })
        }
        EC_INSN_ABORT_LOWER | EC_INSN_ABORT_SAME => ExceptionClass::InstructionAbort {
            address: exc.physical_address,
            fault_code: (syndrome & 0x3f) as u8,
        },
        EC_SOFTWARE_BREAKPOINT => {
            let imm16 = (syndrome & 0xffff) as u16;
            ExceptionClass::SoftwareBreakpoint(imm16)
        }
        EC_WFI_WFE => ExceptionClass::WaitForInterrupt,
        EC_HVC => {
            let imm16 = (syndrome & 0xffff) as u16;
            ExceptionClass::HypercallHvc(imm16)
        }
        EC_SMC => {
            let imm16 = (syndrome & 0xffff) as u16;
            ExceptionClass::SmcCall(imm16)
        }
        EC_SYS_REG => {
            // ARM ESR_EL2 ISS encoding for system register access (EC=0x18):
            //   bit[0]     = Direction: 0 = MSR (guest writes sysreg), 1 = MRS (guest reads sysreg)
            //   bit[4:1]   = CRm
            //   bit[9:5]   = Rt (target GP register)
            //   bit[13:10] = CRn
            //   bit[16:14] = Op1
            //   bit[19:17] = Op2
            //   bit[21:20] = Op0
            let is_write = (syndrome & 1) == 0; // Direction=0 → MSR → write to sysreg
            let crm = ((syndrome >> 1) & 0xf) as u8;
            let rt = ((syndrome >> 5) & 0x1f) as u8;
            let crn = ((syndrome >> 10) & 0xf) as u8;
            let op1 = ((syndrome >> 14) & 0x7) as u8;
            let op2 = ((syndrome >> 17) & 0x7) as u8;
            let op0 = ((syndrome >> 20) & 0x3) as u8;

            ExceptionClass::SystemRegister {
                op0,
                op1,
                crn,
                crm,
                op2,
                is_write,
                rt,
            }
        }
        other => ExceptionClass::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a syndrome value for a data abort with the given parameters.
    fn data_abort_syndrome(ec: u8, sas: u8, is_write: bool, reg: u8, sext: bool) -> u64 {
        let mut s: u64 = 0;
        s |= u64::from(ec) << 26;
        s |= u64::from(sas) << 22;
        if sext {
            s |= 1 << 21;
        }
        s |= u64::from(reg) << 16;
        if is_write {
            s |= 1 << 6;
        }
        s
    }

    #[test]
    fn parse_canceled() {
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_CANCELED,
            exception: ffi::HvVcpuExitException {
                syndrome: 0,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        assert!(matches!(parse_exit(&info), VcpuExit::Canceled));
    }

    #[test]
    fn parse_vtimer() {
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_VTIMER_ACTIVATED,
            exception: ffi::HvVcpuExitException {
                syndrome: 0,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        assert!(matches!(parse_exit(&info), VcpuExit::VtimerActivated));
    }

    #[test]
    fn parse_unknown_reason() {
        let info = ffi::HvVcpuExitInfo {
            reason: 0xff,
            exception: ffi::HvVcpuExitException {
                syndrome: 0,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        assert!(matches!(parse_exit(&info), VcpuExit::Unknown(0xff)));
    }

    #[test]
    fn parse_data_abort_write_4byte() {
        let syndrome = data_abort_syndrome(EC_DATA_ABORT_LOWER, 2, true, 5, false);
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0x0900_0000,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::DataAbort(mmio),
                ..
            } => {
                assert!(mmio.is_write);
                assert_eq!(mmio.access_size, 4);
                assert_eq!(mmio.register, 5);
                assert_eq!(mmio.address, 0x0900_0000);
                assert!(!mmio.sign_extend);
            }
            other => panic!("expected DataAbort, got {other:?}"),
        }
    }

    #[test]
    fn parse_data_abort_read_1byte_sign_extend() {
        let syndrome = data_abort_syndrome(EC_DATA_ABORT_SAME, 0, false, 3, true);
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0x4000,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::DataAbort(mmio),
                ..
            } => {
                assert!(!mmio.is_write);
                assert_eq!(mmio.access_size, 1);
                assert_eq!(mmio.register, 3);
                assert!(mmio.sign_extend);
            }
            other => panic!("expected DataAbort, got {other:?}"),
        }
    }

    #[test]
    fn parse_wfi() {
        let syndrome = u64::from(EC_WFI_WFE) << 26;
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::WaitForInterrupt,
                ..
            } => {}
            other => panic!("expected WFI, got {other:?}"),
        }
    }

    #[test]
    fn parse_hvc() {
        let syndrome = (u64::from(EC_HVC) << 26) | 0x1234;
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::HypercallHvc(imm),
                ..
            } => {
                assert_eq!(imm, 0x1234);
            }
            other => panic!("expected HVC, got {other:?}"),
        }
    }

    #[test]
    fn parse_smc() {
        let syndrome = (u64::from(EC_SMC) << 26) | 0xabcd;
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::SmcCall(imm),
                ..
            } => {
                assert_eq!(imm, 0xabcd);
            }
            other => panic!("expected SMC, got {other:?}"),
        }
    }

    #[test]
    fn access_size_encoding() {
        // SAS=0 → 1, SAS=1 → 2, SAS=2 → 4, SAS=3 → 8
        for (sas, expected) in [(0u8, 1u8), (1, 2), (2, 4), (3, 8)] {
            let syndrome = data_abort_syndrome(EC_DATA_ABORT_LOWER, sas, false, 0, false);
            let info = ffi::HvVcpuExitInfo {
                reason: ffi::HV_EXIT_REASON_EXCEPTION,
                exception: ffi::HvVcpuExitException {
                    syndrome,
                    virtual_address: 0,
                    physical_address: 0,
                },
            };
            match parse_exit(&info) {
                VcpuExit::Exception {
                    class: ExceptionClass::DataAbort(mmio),
                    ..
                } => {
                    assert_eq!(mmio.access_size, expected, "SAS={sas}");
                }
                other => panic!("expected DataAbort for SAS={sas}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_instruction_abort() {
        // IFSC = 0x04 (translation fault, level 0)
        let syndrome = (u64::from(EC_INSN_ABORT_LOWER) << 26) | 0x04;
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0x4000_0000,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class:
                    ExceptionClass::InstructionAbort {
                        address,
                        fault_code,
                    },
                ..
            } => {
                assert_eq!(address, 0x4000_0000);
                assert_eq!(fault_code, 0x04);
            }
            other => panic!("expected InstructionAbort, got {other:?}"),
        }
    }

    #[test]
    fn parse_software_breakpoint() {
        let syndrome = (u64::from(EC_SOFTWARE_BREAKPOINT) << 26) | 0x42;
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::SoftwareBreakpoint(imm),
                ..
            } => {
                assert_eq!(imm, 0x42);
            }
            other => panic!("expected SoftwareBreakpoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_system_register_msr() {
        // Encode MSR (write) for SCTLR_EL1: Op0=3 Op1=0 CRn=1 CRm=0 Op2=0, Rt=5
        // ISS: direction=0 (write) at bit 0
        //   bit [20:19] = Op0 = 3   → 0b11 << 19
        //   bit [18:16] = Op2 = 0   → 0
        //   bit [15:12] = CRn = 1   → 0b0001 << 12
        //   bit [11:8]  = nothing (reserved)
        //   bit [9:5]   = Rt = 5    → 5 << 5
        //   bit [4:1]   = CRm = 0   → 0
        //   bit [0]     = direction: 0 = write (MSR)
        let iss: u64 = (3 << 20) | (1 << 10) | (5 << 5); // Op0=3 CRn=1 Rt=5 direction=write(0)
        let syndrome = (u64::from(EC_SYS_REG) << 26) | iss;
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class:
                    ExceptionClass::SystemRegister {
                        op0,
                        op1,
                        crn,
                        crm,
                        op2,
                        is_write,
                        rt,
                    },
                ..
            } => {
                assert_eq!(op0, 3);
                assert!(is_write); // MSR = write
                assert_eq!(rt, 5);
                // Verify crn/crm/op1/op2 are correctly extracted
                assert_eq!(crn, 1);
                assert_eq!(crm, 0);
                assert_eq!(op1, 0);
                assert_eq!(op2, 0);
            }
            other => panic!("expected SystemRegister, got {other:?}"),
        }
    }

    #[test]
    fn parse_system_register_mrs() {
        // Encode MRS (read) for SCTLR_EL1: Op0=3 Op1=0 CRn=1 CRm=0 Op2=0, Rt=7
        // ISS: direction=1 (read) at bit 0
        let iss: u64 = (3 << 20) | (1 << 10) | (7 << 5) | 1; // Op0=3 CRn=1 Rt=7 direction=read(1)
        let syndrome = (u64::from(EC_SYS_REG) << 26) | iss;
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class:
                    ExceptionClass::SystemRegister {
                        op0,
                        op1,
                        crn,
                        crm,
                        op2,
                        is_write,
                        rt,
                    },
                ..
            } => {
                assert_eq!(op0, 3);
                assert!(!is_write); // MRS = read
                assert_eq!(rt, 7);
                assert_eq!(crn, 1);
                assert_eq!(crm, 0);
                assert_eq!(op1, 0);
                assert_eq!(op2, 0);
            }
            other => panic!("expected SystemRegister, got {other:?}"),
        }
    }

    #[test]
    fn parse_data_abort_8byte() {
        // SAS=3 → 8-byte access
        let syndrome = data_abort_syndrome(EC_DATA_ABORT_LOWER, 3, false, 0, false);
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0x0a00_0100,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::DataAbort(mmio),
                ..
            } => {
                assert_eq!(mmio.access_size, 8);
                assert!(!mmio.is_write);
            }
            other => panic!("expected DataAbort, got {other:?}"),
        }
    }

    #[test]
    fn parse_data_abort_register_31_xzr() {
        // Register 31 = XZR (zero register) on reads, SP on some contexts
        let syndrome = data_abort_syndrome(EC_DATA_ABORT_LOWER, 2, true, 31, false);
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::DataAbort(mmio),
                ..
            } => {
                assert_eq!(mmio.register, 31);
            }
            other => panic!("expected DataAbort, got {other:?}"),
        }
    }

    #[test]
    fn parse_unhandled_ec_falls_through() {
        // EC=0x2F is not a known exception class
        let syndrome = u64::from(0x2Fu8) << 26;
        let info = ffi::HvVcpuExitInfo {
            reason: ffi::HV_EXIT_REASON_EXCEPTION,
            exception: ffi::HvVcpuExitException {
                syndrome,
                virtual_address: 0,
                physical_address: 0,
            },
        };
        match parse_exit(&info) {
            VcpuExit::Exception {
                class: ExceptionClass::Other(ec),
                ..
            } => {
                assert_eq!(ec, 0x2f);
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }
}

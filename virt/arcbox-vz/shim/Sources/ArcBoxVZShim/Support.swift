// Host capability queries (mirrors src/ffi/mod.rs "System Queries").

import Virtualization

func vzSupported() -> Bool {
    VZVirtualMachine.isSupported
}

func vzMinCPUCount() -> UInt64 {
    UInt64(VZVirtualMachineConfiguration.minimumAllowedCPUCount)
}

func vzMaxCPUCount() -> UInt64 {
    UInt64(VZVirtualMachineConfiguration.maximumAllowedCPUCount)
}

func vzMinMemorySize() -> UInt64 {
    VZVirtualMachineConfiguration.minimumAllowedMemorySize
}

func vzMaxMemorySize() -> UInt64 {
    VZVirtualMachineConfiguration.maximumAllowedMemorySize
}

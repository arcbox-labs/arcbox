// VM configuration, boot loaders, and the generic platform
// (mirrors src/configuration/{vm_config,boot_loader,platform}.rs).
//
// Configuration objects are queue-free: VZ only requires queue affinity for
// a live VZVirtualMachine, so these run on the caller's (Rust) thread.

import Virtualization

func configNew() -> UnsafeMutableRawPointer {
    abxRetainedHandle(VZVirtualMachineConfiguration())
}

func configSetCPUCount(_ config: UnsafeMutableRawPointer, _ count: UInt64) {
    abxBorrow(config, as: VZVirtualMachineConfiguration.self).cpuCount = Int(count)
}

func configCPUCount(_ config: UnsafeMutableRawPointer) -> UInt64 {
    UInt64(abxBorrow(config, as: VZVirtualMachineConfiguration.self).cpuCount)
}

func configSetMemorySize(_ config: UnsafeMutableRawPointer, _ bytes: UInt64) {
    abxBorrow(config, as: VZVirtualMachineConfiguration.self).memorySize = bytes
}

func configMemorySize(_ config: UnsafeMutableRawPointer) -> UInt64 {
    abxBorrow(config, as: VZVirtualMachineConfiguration.self).memorySize
}

func configSetBootLoader(_ config: UnsafeMutableRawPointer, _ bootLoader: UnsafeMutableRawPointer) {
    abxBorrow(config, as: VZVirtualMachineConfiguration.self).bootLoader =
        abxBorrow(bootLoader, as: VZBootLoader.self)
}

func configSetPlatform(_ config: UnsafeMutableRawPointer, _ platform: UnsafeMutableRawPointer) {
    abxBorrow(config, as: VZVirtualMachineConfiguration.self).platform =
        abxBorrow(platform, as: VZPlatformConfiguration.self)
}

func configValidate(
    _ config: UnsafeMutableRawPointer,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    do {
        try abxBorrow(config, as: VZVirtualMachineConfiguration.self).validate()
        return true
    } catch {
        errorOut?.pointee = abxErrorString(error)
        return false
    }
}

func bootLoaderLinuxNew(_ kernelPath: UnsafePointer<CChar>) -> UnsafeMutableRawPointer {
    let url = URL(fileURLWithPath: String(cString: kernelPath))
    return abxRetainedHandle(VZLinuxBootLoader(kernelURL: url))
}

func bootLoaderLinuxSetInitrd(
    _ bootLoader: UnsafeMutableRawPointer, _ path: UnsafePointer<CChar>
) {
    let url = URL(fileURLWithPath: String(cString: path))
    abxBorrow(bootLoader, as: VZLinuxBootLoader.self).initialRamdiskURL = url
}

func bootLoaderLinuxSetCmdline(
    _ bootLoader: UnsafeMutableRawPointer, _ cmdline: UnsafePointer<CChar>
) {
    abxBorrow(bootLoader, as: VZLinuxBootLoader.self).commandLine = String(cString: cmdline)
}

func bootLoaderMacOSNew() -> UnsafeMutableRawPointer {
    abxRetainedHandle(VZMacOSBootLoader())
}

func platformGenericNew() -> UnsafeMutableRawPointer {
    abxRetainedHandle(VZGenericPlatformConfiguration())
}

func platformGenericNestedSupported() -> Bool {
    if #available(macOS 15.0, *) {
        return VZGenericPlatformConfiguration.isNestedVirtualizationSupported
    }
    return false
}

func platformGenericSetNested(_ platform: UnsafeMutableRawPointer, _ enabled: Bool) {
    if #available(macOS 15.0, *) {
        abxBorrow(platform, as: VZGenericPlatformConfiguration.self)
            .isNestedVirtualizationEnabled = enabled
    }
}

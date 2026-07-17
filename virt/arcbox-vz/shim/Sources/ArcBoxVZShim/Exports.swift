// ALL @_cdecl exports live in this file, in the NORMATIVE SYMBOL ORDER.
//
// CONTRACT: src/shim_ffi.rs declares these symbols in the exact same order —
// review the two files side by side. Any signature or semantics change bumps
// `abxShimABIVersion` (Errors.swift) and `ABX_SHIM_ABI_VERSION` (shim_ffi.rs).

import Foundation

// MARK: - Errors / strings / handles

@_cdecl("abx_shim_version")
public func abxShimVersion() -> UInt32 {
    abxShimABIVersion
}

@_cdecl("abx_string_free")
public func abxStringFree(_ ptr: UnsafeMutablePointer<CChar>?) {
    free(ptr)
}

@_cdecl("abx_bytes_free")
public func abxBytesFree(_ ptr: UnsafeMutableRawPointer?) {
    free(ptr)
}

@_cdecl("abx_object_release")
public func abxObjectRelease(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else { return }
    Unmanaged<AnyObject>.fromOpaque(handle).release()
}

// MARK: - Support (host capability queries)

@_cdecl("abx_vz_supported")
public func abxVzSupported() -> Bool {
    vzSupported()
}

@_cdecl("abx_vz_min_cpu_count")
public func abxVzMinCPUCount() -> UInt64 {
    vzMinCPUCount()
}

@_cdecl("abx_vz_max_cpu_count")
public func abxVzMaxCPUCount() -> UInt64 {
    vzMaxCPUCount()
}

@_cdecl("abx_vz_min_memory_size")
public func abxVzMinMemorySize() -> UInt64 {
    vzMinMemorySize()
}

@_cdecl("abx_vz_max_memory_size")
public func abxVzMaxMemorySize() -> UInt64 {
    vzMaxMemorySize()
}

// MARK: - Configuration

@_cdecl("abx_config_new")
public func abxConfigNew() -> UnsafeMutableRawPointer {
    configNew()
}

@_cdecl("abx_config_set_cpu_count")
public func abxConfigSetCPUCount(_ config: UnsafeMutableRawPointer, _ count: UInt64) {
    configSetCPUCount(config, count)
}

@_cdecl("abx_config_cpu_count")
public func abxConfigCPUCount(_ config: UnsafeMutableRawPointer) -> UInt64 {
    configCPUCount(config)
}

@_cdecl("abx_config_set_memory_size")
public func abxConfigSetMemorySize(_ config: UnsafeMutableRawPointer, _ bytes: UInt64) {
    configSetMemorySize(config, bytes)
}

@_cdecl("abx_config_memory_size")
public func abxConfigMemorySize(_ config: UnsafeMutableRawPointer) -> UInt64 {
    configMemorySize(config)
}

@_cdecl("abx_config_set_boot_loader")
public func abxConfigSetBootLoader(
    _ config: UnsafeMutableRawPointer, _ bootLoader: UnsafeMutableRawPointer
) {
    configSetBootLoader(config, bootLoader)
}

@_cdecl("abx_config_set_platform")
public func abxConfigSetPlatform(
    _ config: UnsafeMutableRawPointer, _ platform: UnsafeMutableRawPointer
) {
    configSetPlatform(config, platform)
}

@_cdecl("abx_config_validate")
public func abxConfigValidate(
    _ config: UnsafeMutableRawPointer,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    configValidate(config, errorOut)
}

// MARK: - Boot loaders

@_cdecl("abx_bootloader_linux_new")
public func abxBootLoaderLinuxNew(_ kernelPath: UnsafePointer<CChar>) -> UnsafeMutableRawPointer {
    bootLoaderLinuxNew(kernelPath)
}

@_cdecl("abx_bootloader_linux_set_initrd")
public func abxBootLoaderLinuxSetInitrd(
    _ bootLoader: UnsafeMutableRawPointer, _ path: UnsafePointer<CChar>
) {
    bootLoaderLinuxSetInitrd(bootLoader, path)
}

@_cdecl("abx_bootloader_linux_set_cmdline")
public func abxBootLoaderLinuxSetCmdline(
    _ bootLoader: UnsafeMutableRawPointer, _ cmdline: UnsafePointer<CChar>
) {
    bootLoaderLinuxSetCmdline(bootLoader, cmdline)
}

@_cdecl("abx_bootloader_macos_new")
public func abxBootLoaderMacOSNew() -> UnsafeMutableRawPointer {
    bootLoaderMacOSNew()
}

// MARK: - Platforms (generic; MacPlatform arrives with the identity types)

@_cdecl("abx_platform_generic_new")
public func abxPlatformGenericNew() -> UnsafeMutableRawPointer {
    platformGenericNew()
}

@_cdecl("abx_platform_generic_nested_supported")
public func abxPlatformGenericNestedSupported() -> Bool {
    platformGenericNestedSupported()
}

@_cdecl("abx_platform_generic_set_nested")
public func abxPlatformGenericSetNested(_ platform: UnsafeMutableRawPointer, _ enabled: Bool) {
    platformGenericSetNested(platform, enabled)
}

// MARK: - Device configurations

@_cdecl("abx_storage_disk_image_new")
public func abxStorageDiskImageNew(
    _ path: UnsafePointer<CChar>,
    _ readOnly: Bool,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    storageDiskImageNew(path, readOnly, errorOut)
}

@_cdecl("abx_network_nat_new")
public func abxNetworkNATNew(
    _ mac: UnsafePointer<CChar>?,
    _ mtu: UInt64,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    networkNATNew(mac, mtu, errorOut)
}

@_cdecl("abx_network_file_handle_new")
public func abxNetworkFileHandleNew(
    _ fd: Int32,
    _ mac: UnsafePointer<CChar>?,
    _ mtu: UInt64,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    networkFileHandleNew(fd, mac, mtu, errorOut)
}

@_cdecl("abx_serial_console_new")
public func abxSerialConsoleNew(_ readFd: Int32, _ writeFd: Int32) -> UnsafeMutableRawPointer {
    serialConsoleNew(readFd, writeFd)
}

@_cdecl("abx_socket_device_config_new")
public func abxSocketDeviceConfigNew() -> UnsafeMutableRawPointer {
    socketDeviceConfigNew()
}

@_cdecl("abx_entropy_new")
public func abxEntropyNew() -> UnsafeMutableRawPointer {
    entropyNew()
}

@_cdecl("abx_balloon_config_new")
public func abxBalloonConfigNew() -> UnsafeMutableRawPointer {
    balloonConfigNew()
}

@_cdecl("abx_graphics_mac_new")
public func abxGraphicsMacNew(
    _ width: Int64, _ height: Int64, _ ppi: Int64
) -> UnsafeMutableRawPointer {
    graphicsMacNew(width, height, ppi)
}

// MARK: - Directory shares / VirtioFS

@_cdecl("abx_shared_directory_new")
public func abxSharedDirectoryNew(
    _ path: UnsafePointer<CChar>, _ readOnly: Bool
) -> UnsafeMutableRawPointer {
    sharedDirectoryNew(path, readOnly)
}

@_cdecl("abx_single_share_new")
public func abxSingleShareNew(_ directory: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    singleShareNew(directory)
}

@_cdecl("abx_rosetta_availability")
public func abxRosettaAvailability() -> Int64 {
    rosettaAvailability()
}

@_cdecl("abx_rosetta_share_new")
public func abxRosettaShareNew(
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    rosettaShareNew(errorOut)
}

@_cdecl("abx_virtiofs_new")
public func abxVirtiofsNew(
    _ tag: UnsafePointer<CChar>,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    virtiofsNew(tag, errorOut)
}

@_cdecl("abx_virtiofs_set_share")
public func abxVirtiofsSetShare(
    _ config: UnsafeMutableRawPointer, _ share: UnsafeMutableRawPointer
) {
    virtiofsSetShare(config, share)
}

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

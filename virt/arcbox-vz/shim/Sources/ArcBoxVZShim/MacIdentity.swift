// macOS guest identity types (mirrors src/configuration/mac.rs) and the
// MacPlatform assembly (mirrors the MacPlatform half of platform.rs).

import Virtualization

/// Copies `data` into a malloc'd buffer owned by the caller (Rust), freed via
/// `abx_bytes_free`. Returns nil (len 0) for empty data.
private func abxDataCopy(
    _ data: Data, _ lengthOut: UnsafeMutablePointer<UInt>?
) -> UnsafeMutableRawPointer? {
    lengthOut?.pointee = UInt(data.count)
    guard !data.isEmpty, let buffer = malloc(data.count) else { return nil }
    data.copyBytes(
        to: UnsafeMutableRawBufferPointer(start: buffer, count: data.count))
    return buffer
}

func macHardwareModelFromData(
    _ bytes: UnsafeRawPointer, _ length: UInt
) -> UnsafeMutableRawPointer? {
    let data = Data(bytes: bytes, count: Int(length))
    guard let model = VZMacHardwareModel(dataRepresentation: data) else { return nil }
    return abxRetainedHandle(model)
}

func macHardwareModelSupported(_ handle: UnsafeMutableRawPointer) -> Bool {
    abxBorrow(handle, as: VZMacHardwareModel.self).isSupported
}

func macHardwareModelData(
    _ handle: UnsafeMutableRawPointer, _ lengthOut: UnsafeMutablePointer<UInt>?
) -> UnsafeMutableRawPointer? {
    abxDataCopy(abxBorrow(handle, as: VZMacHardwareModel.self).dataRepresentation, lengthOut)
}

func macMachineIdNew() -> UnsafeMutableRawPointer {
    abxRetainedHandle(VZMacMachineIdentifier())
}

func macMachineIdFromData(
    _ bytes: UnsafeRawPointer, _ length: UInt
) -> UnsafeMutableRawPointer? {
    let data = Data(bytes: bytes, count: Int(length))
    guard let identifier = VZMacMachineIdentifier(dataRepresentation: data) else { return nil }
    return abxRetainedHandle(identifier)
}

func macMachineIdData(
    _ handle: UnsafeMutableRawPointer, _ lengthOut: UnsafeMutablePointer<UInt>?
) -> UnsafeMutableRawPointer? {
    abxDataCopy(abxBorrow(handle, as: VZMacMachineIdentifier.self).dataRepresentation, lengthOut)
}

func auxStorageOpen(_ path: UnsafePointer<CChar>) -> UnsafeMutableRawPointer {
    let url = URL(fileURLWithPath: String(cString: path))
    return abxRetainedHandle(VZMacAuxiliaryStorage(url: url))
}

func auxStorageCreate(
    _ path: UnsafePointer<CChar>,
    _ hardwareModel: UnsafeMutableRawPointer,
    _ overwrite: Bool,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    let url = URL(fileURLWithPath: String(cString: path))
    let model = abxBorrow(hardwareModel, as: VZMacHardwareModel.self)
    do {
        let storage = try VZMacAuxiliaryStorage(
            creatingStorageAt: url,
            hardwareModel: model,
            options: overwrite ? [.allowOverwrite] : [])
        return abxRetainedHandle(storage)
    } catch {
        errorOut?.pointee = abxErrorString(error)
        return nil
    }
}

func platformMacNew(
    _ hardwareModel: UnsafeMutableRawPointer,
    _ machineIdentifier: UnsafeMutableRawPointer,
    _ auxiliaryStorage: UnsafeMutableRawPointer
) -> UnsafeMutableRawPointer {
    // The platform's properties are strong, so the borrows do not consume
    // the caller's +1 references.
    let platform = VZMacPlatformConfiguration()
    platform.hardwareModel = abxBorrow(hardwareModel, as: VZMacHardwareModel.self)
    platform.machineIdentifier = abxBorrow(machineIdentifier, as: VZMacMachineIdentifier.self)
    platform.auxiliaryStorage = abxBorrow(auxiliaryStorage, as: VZMacAuxiliaryStorage.self)
    return abxRetainedHandle(platform)
}

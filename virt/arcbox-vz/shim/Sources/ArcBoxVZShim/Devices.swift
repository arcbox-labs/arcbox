// Device configuration constructors (mirrors src/device/*.rs).
//
// Policy knobs stay on the Rust side (e.g. the ARCBOX_DIAG_NET_MTU_4000 MTU
// override is read and logged there); this file only performs the VZ calls.

import Virtualization

func storageDiskImageNew(
    _ path: UnsafePointer<CChar>,
    _ readOnly: Bool,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    let url = URL(fileURLWithPath: String(cString: path))
    do {
        let attachment = try VZDiskImageStorageDeviceAttachment(url: url, readOnly: readOnly)
        return abxRetainedHandle(VZVirtioBlockDeviceConfiguration(attachment: attachment))
    } catch {
        errorOut?.pointee = abxErrorString(error)
        return nil
    }
}

/// Shared tail for the network constructors: MAC assignment + optional MTU.
private func networkConfig(
    attachment: VZNetworkDeviceAttachment,
    mac: UnsafePointer<CChar>?,
    mtu: UInt64,
    errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    if mtu > 0, let fileHandleAttachment = attachment as? VZFileHandleNetworkDeviceAttachment {
        fileHandleAttachment.maximumTransmissionUnit = Int(mtu)
    }
    let config = VZVirtioNetworkDeviceConfiguration()
    config.attachment = attachment
    if let mac {
        guard let address = VZMACAddress(string: String(cString: mac)) else {
            errorOut?.pointee = abxStrdup("invalid MAC address: \(String(cString: mac))")
            return nil
        }
        config.macAddress = address
    } else {
        config.macAddress = VZMACAddress.randomLocallyAdministered()
    }
    return abxRetainedHandle(config)
}

func networkNATNew(
    _ mac: UnsafePointer<CChar>?,
    _ mtu: UInt64,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    networkConfig(
        attachment: VZNATNetworkDeviceAttachment(), mac: mac, mtu: mtu, errorOut: errorOut)
}

func networkFileHandleNew(
    _ fd: Int32,
    _ mac: UnsafePointer<CChar>?,
    _ mtu: UInt64,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
    let attachment = VZFileHandleNetworkDeviceAttachment(fileHandle: handle)
    return networkConfig(attachment: attachment, mac: mac, mtu: mtu, errorOut: errorOut)
}

func serialConsoleNew(_ readFd: Int32, _ writeFd: Int32) -> UnsafeMutableRawPointer {
    let attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: FileHandle(fileDescriptor: readFd, closeOnDealloc: false),
        fileHandleForWriting: FileHandle(fileDescriptor: writeFd, closeOnDealloc: false))
    let config = VZVirtioConsoleDeviceSerialPortConfiguration()
    config.attachment = attachment
    return abxRetainedHandle(config)
}

func socketDeviceConfigNew() -> UnsafeMutableRawPointer {
    abxRetainedHandle(VZVirtioSocketDeviceConfiguration())
}

func entropyNew() -> UnsafeMutableRawPointer {
    abxRetainedHandle(VZVirtioEntropyDeviceConfiguration())
}

func balloonConfigNew() -> UnsafeMutableRawPointer {
    abxRetainedHandle(VZVirtioTraditionalMemoryBalloonDeviceConfiguration())
}

func graphicsMacNew(_ width: Int64, _ height: Int64, _ ppi: Int64) -> UnsafeMutableRawPointer {
    let display = VZMacGraphicsDisplayConfiguration(
        widthInPixels: Int(width), heightInPixels: Int(height), pixelsPerInch: Int(ppi))
    let device = VZMacGraphicsDeviceConfiguration()
    device.displays = [display]
    return abxRetainedHandle(device)
}

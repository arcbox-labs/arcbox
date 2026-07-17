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

// MARK: Directory shares / VirtioFS

func sharedDirectoryNew(_ path: UnsafePointer<CChar>, _ readOnly: Bool) -> UnsafeMutableRawPointer {
    let url = URL(fileURLWithPath: String(cString: path))
    return abxRetainedHandle(VZSharedDirectory(url: url, readOnly: readOnly))
}

func singleShareNew(_ directory: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    // VZSingleDirectoryShare retains the directory; the borrow does not
    // consume the caller's +1.
    abxRetainedHandle(
        VZSingleDirectoryShare(directory: abxBorrow(directory, as: VZSharedDirectory.self)))
}

/// Raw values match `VZLinuxRosettaAvailability` (0 notSupported,
/// 1 notInstalled, 2 installed) — the Rust side maps them.
func rosettaAvailability() -> Int64 {
    Int64(VZLinuxRosettaDirectoryShare.availability.rawValue)
}

func rosettaShareNew(
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        return abxRetainedHandle(try VZLinuxRosettaDirectoryShare())
    } catch {
        errorOut?.pointee = abxErrorString(error)
        return nil
    }
}

func virtiofsNew(
    _ tag: UnsafePointer<CChar>,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    let tagString = String(cString: tag)
    do {
        try VZVirtioFileSystemDeviceConfiguration.validateTag(tagString)
    } catch {
        errorOut?.pointee = abxErrorString(error)
        return nil
    }
    return abxRetainedHandle(VZVirtioFileSystemDeviceConfiguration(tag: tagString))
}

func virtiofsSetShare(_ config: UnsafeMutableRawPointer, _ share: UnsafeMutableRawPointer) {
    // The config retains the share; the borrow does not consume the +1.
    abxBorrow(config, as: VZVirtioFileSystemDeviceConfiguration.self).share =
        abxBorrow(share, as: VZDirectoryShare.self)
}

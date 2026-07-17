// macOS restore images and the IPSW installer (mirrors src/restore.rs).
//
// Restore-image loads complete on a framework-internal queue; the installer
// itself is queue-affine (its initializer dispatch_asserts the VM queue), so
// construction and install-kickoff go through the VM box's queue.

import Virtualization

/// Object-producing completion: fires exactly once with either a +1 handle
/// (owned by the receiver) or a strdup'd error message.
public typealias ABXObjectCallback =
    @convention(c) (
        UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?
    ) -> Void

/// Pairs the installer with the VM's serial queue for install-kickoff.
final class ABXInstallerBox {
    let installer: VZMacOSInstaller
    let queue: DispatchQueue

    init(installer: VZMacOSInstaller, queue: DispatchQueue) {
        self.installer = installer
        self.queue = queue
    }
}

private func deliverImage(
    _ result: Result<VZMacOSRestoreImage, Error>,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: ABXObjectCallback
) {
    switch result {
    case .success(let image):
        callback(ctx, abxRetainedHandle(image), nil)
    case .failure(let error):
        callback(ctx, nil, abxErrorString(error))
    }
}

func restoreImageLoad(
    _ path: UnsafePointer<CChar>,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: @escaping ABXObjectCallback
) {
    let url = URL(fileURLWithPath: String(cString: path))
    VZMacOSRestoreImage.load(from: url) { result in
        deliverImage(result, ctx, callback)
    }
}

func restoreImageFetchLatest(
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: @escaping ABXObjectCallback
) {
    VZMacOSRestoreImage.fetchLatestSupported { result in
        deliverImage(result, ctx, callback)
    }
}

/// Extracts the most-featureful supported configuration: hardware model
/// (+1 handle), minimum CPU count, and minimum memory size.
func restoreImageRequirements(
    _ image: UnsafeMutableRawPointer,
    _ hardwareModelOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ minCPUOut: UnsafeMutablePointer<UInt64>?,
    _ minMemoryOut: UnsafeMutablePointer<UInt64>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    let restoreImage = abxBorrow(image, as: VZMacOSRestoreImage.self)
    guard let requirements = restoreImage.mostFeaturefulSupportedConfiguration else {
        errorOut?.pointee = abxStrdup("restore image has no supported configuration")
        return false
    }
    hardwareModelOut?.pointee = abxRetainedHandle(requirements.hardwareModel)
    minCPUOut?.pointee = UInt64(requirements.minimumSupportedCPUCount)
    minMemoryOut?.pointee = requirements.minimumSupportedMemorySize
    return true
}

/// Returns the image URL as a strdup'd absolute string, or nil.
func restoreImageURL(_ image: UnsafeMutableRawPointer) -> UnsafeMutablePointer<CChar>? {
    abxStrdup(abxBorrow(image, as: VZMacOSRestoreImage.self).url.absoluteString)
}

func installerNew(
    _ vmBox: UnsafeMutableRawPointer,
    _ ipswPath: UnsafePointer<CChar>
) -> UnsafeMutableRawPointer {
    let box = abxBorrow(vmBox, as: ABXVMBox.self)
    let url = URL(fileURLWithPath: String(cString: ipswPath))
    // VZMacOSInstaller's initializer dispatch_asserts the VM's queue.
    let installer = box.queue.sync {
        VZMacOSInstaller(virtualMachine: box.vm, restoringFromImageAt: url)
    }
    return abxRetainedHandle(ABXInstallerBox(installer: installer, queue: box.queue))
}

/// Install progress as a fraction in 0.0...1.0 (NSProgress read; queue-free).
func installerFraction(_ box: UnsafeMutableRawPointer) -> Double {
    abxBorrow(box, as: ABXInstallerBox.self).installer.progress.fractionCompleted
}

func installerInstall(
    _ box: UnsafeMutableRawPointer,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: @escaping ABXStateCallback
) {
    let installerBox = abxBorrow(box, as: ABXInstallerBox.self)
    installerBox.queue.sync {
        installerBox.installer.install { result in
            switch result {
            case .success:
                callback(ctx, nil)
            case .failure(let error):
                callback(ctx, abxErrorString(error))
            }
        }
    }
}

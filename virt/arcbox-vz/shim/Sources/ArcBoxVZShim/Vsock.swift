// Vsock connect (mirrors src/socket.rs).
//
// VZVirtioSocketDevice is queue-affine: connect must be issued on the VM's
// dispatch queue, and VZ delivers the completion on that same queue. The fd
// is dup'd INSIDE the completion handler because VZ closes the original when
// the VZVirtioSocketConnection deallocates after the callback returns.

import Virtualization

/// Callback shape for vsock connects: fires exactly once with either a dup'd
/// fd (+ ports) or a strdup'd error message.
public typealias ABXVsockCallback =
    @convention(c) (
        UnsafeMutableRawPointer?, Int32, UInt32, UInt32, UnsafeMutablePointer<CChar>?
    ) -> Void

/// Pairs a socket device with the owning VM's serial queue (mirroring what
/// the Rust `VirtioSocketDevice` struct holds).
final class ABXSocketDeviceBox {
    let device: VZVirtioSocketDevice
    let queue: DispatchQueue

    init(device: VZVirtioSocketDevice, queue: DispatchQueue) {
        self.device = device
        self.queue = queue
    }
}

/// Migration-only: wraps raw (device, queue) ObjC pointers produced by the
/// pre-shim `socket_devices()` path. Dies once the lifecycle PR hands out
/// boxes directly.
func socketDeviceBoxFromRaw(
    _ device: UnsafeMutableRawPointer, _ queue: UnsafeMutableRawPointer
) -> UnsafeMutableRawPointer {
    abxRetainedHandle(
        ABXSocketDeviceBox(
            device: abxBorrow(device, as: VZVirtioSocketDevice.self),
            queue: abxBorrow(queue, as: DispatchQueue.self)))
}

func vsockConnect(
    _ box: UnsafeMutableRawPointer,
    _ port: UInt32,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: ABXVsockCallback
) {
    let deviceBox = abxBorrow(box, as: ABXSocketDeviceBox.self)
    deviceBox.queue.async {
        deviceBox.device.connect(toPort: port) { result in
            switch result {
            case .success(let connection):
                let fd = dup(connection.fileDescriptor)
                if fd < 0 {
                    let message = String(cString: strerror(errno))
                    callback(ctx, -1, 0, 0, abxStrdup("failed to dup vsock fd: \(message)"))
                    return
                }
                callback(ctx, fd, connection.sourcePort, connection.destinationPort, nil)
            case .failure(let error):
                callback(ctx, -1, 0, 0, abxErrorString(error))
            }
        }
    }
}

// VM lifecycle (mirrors src/vm.rs).
//
// Every VZVirtualMachine access is issued on the VM's serial queue (VZ
// asserts queue affinity). Lifecycle calls dispatch the VZ operation via
// queue.sync — the VZ method itself returns after scheduling, and its
// completion handler fires later on the same queue, exactly once.

import Virtualization

/// Lifecycle completion: fires exactly once, from the VM's dispatch queue,
/// with null on success or a strdup'd error message.
public typealias ABXStateCallback =
    @convention(c) (
        UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?
    ) -> Void

/// Pairs a VZVirtualMachine with its serial queue (mirroring what the Rust
/// `VirtualMachine` struct holds).
final class ABXVMBox {
    let vm: VZVirtualMachine
    let queue: DispatchQueue

    init(vm: VZVirtualMachine, queue: DispatchQueue) {
        self.vm = vm
        self.queue = queue
    }
}

/// Pairs a balloon device with the owning VM's serial queue (VZ device
/// objects are queue-affine).
final class ABXBalloonBox {
    let device: VZMemoryBalloonDevice
    let queue: DispatchQueue

    init(device: VZMemoryBalloonDevice, queue: DispatchQueue) {
        self.device = device
        self.queue = queue
    }
}

/// Device-array kinds for `configSetDevices`; values are part of the C ABI
/// (mirrored by the Rust caller).
enum ABXDeviceKind: UInt32 {
    case storage = 0
    case network = 1
    case serial = 2
    case socket = 3
    case entropy = 4
    case directorySharing = 5
    case memoryBalloon = 6
    case graphics = 7
}

/// Applies one device array onto the configuration, borrowing every handle
/// (the configuration retains; the caller keeps its +1s).
func configSetDevices(
    _ config: UnsafeMutableRawPointer,
    _ kind: UInt32,
    _ items: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ count: UInt
) {
    let cfg = abxBorrow(config, as: VZVirtualMachineConfiguration.self)
    var handles: [UnsafeMutableRawPointer] = []
    if let items {
        for index in 0..<Int(count) {
            if let handle = items[index] {
                handles.append(handle)
            }
        }
    }
    guard let deviceKind = ABXDeviceKind(rawValue: kind) else {
        fatalError("configSetDevices: unknown device kind \(kind) — Rust/Swift kind maps drifted")
    }
    switch deviceKind {
    case .storage:
        cfg.storageDevices = handles.map { abxBorrow($0, as: VZStorageDeviceConfiguration.self) }
    case .network:
        cfg.networkDevices = handles.map {
            abxBorrow($0, as: VZNetworkDeviceConfiguration.self)
        }
    case .serial:
        cfg.serialPorts = handles.map { abxBorrow($0, as: VZSerialPortConfiguration.self) }
    case .socket:
        cfg.socketDevices = handles.map { abxBorrow($0, as: VZSocketDeviceConfiguration.self) }
    case .entropy:
        cfg.entropyDevices = handles.map { abxBorrow($0, as: VZEntropyDeviceConfiguration.self) }
    case .directorySharing:
        cfg.directorySharingDevices = handles.map {
            abxBorrow($0, as: VZDirectorySharingDeviceConfiguration.self)
        }
    case .memoryBalloon:
        cfg.memoryBalloonDevices = handles.map {
            abxBorrow($0, as: VZMemoryBalloonDeviceConfiguration.self)
        }
    case .graphics:
        cfg.graphicsDevices = handles.map { abxBorrow($0, as: VZGraphicsDeviceConfiguration.self) }
    }
}

/// Creates the VM on a fresh serial queue and returns its box.
///
/// The raw out-params are transitional (the installer still drives the raw
/// VZVirtualMachine on its queue from the Rust side); they die with the
/// installer migration. Both are borrowed views kept alive by the box.
func vmNew(
    _ config: UnsafeMutableRawPointer,
    _ rawVmOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ rawQueueOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer {
    let cfg = abxBorrow(config, as: VZVirtualMachineConfiguration.self)
    let queue = DispatchQueue(label: "com.arcbox.vz.vm")
    let vm = VZVirtualMachine(configuration: cfg, queue: queue)
    rawVmOut?.pointee = Unmanaged.passUnretained(vm).toOpaque()
    rawQueueOut?.pointee = Unmanaged.passUnretained(queue).toOpaque()
    return abxRetainedHandle(ABXVMBox(vm: vm, queue: queue))
}

/// Raw values match `VZVirtualMachine.State` (stopped=0 … restoring=9); the
/// Rust `VirtualMachineState` enum mirrors them.
func vmState(_ box: UnsafeMutableRawPointer) -> Int64 {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync { Int64(vmBox.vm.state.rawValue) }
}

func vmCanStop(_ box: UnsafeMutableRawPointer) -> Bool {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync { vmBox.vm.canStop }
}

func vmCanPause(_ box: UnsafeMutableRawPointer) -> Bool {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync { vmBox.vm.canPause }
}

func vmCanResume(_ box: UnsafeMutableRawPointer) -> Bool {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync { vmBox.vm.canResume }
}

func vmRequestStop(
    _ box: UnsafeMutableRawPointer,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync {
        do {
            try vmBox.vm.requestStop()
            return true
        } catch {
            errorOut?.pointee = abxErrorString(error)
            return false
        }
    }
}

func vmStart(
    _ box: UnsafeMutableRawPointer,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: @escaping ABXStateCallback
) {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    vmBox.queue.sync {
        vmBox.vm.start { result in
            switch result {
            case .success:
                callback(ctx, nil)
            case .failure(let error):
                callback(ctx, abxErrorString(error))
            }
        }
    }
}

func vmStop(
    _ box: UnsafeMutableRawPointer,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: @escaping ABXStateCallback
) {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    vmBox.queue.sync {
        vmBox.vm.stop { error in
            if let error {
                callback(ctx, abxErrorString(error))
            } else {
                callback(ctx, nil)
            }
        }
    }
}

func vmPause(
    _ box: UnsafeMutableRawPointer,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: @escaping ABXStateCallback
) {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    vmBox.queue.sync {
        vmBox.vm.pause { result in
            switch result {
            case .success:
                callback(ctx, nil)
            case .failure(let error):
                callback(ctx, abxErrorString(error))
            }
        }
    }
}

func vmResume(
    _ box: UnsafeMutableRawPointer,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: @escaping ABXStateCallback
) {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    vmBox.queue.sync {
        vmBox.vm.resume { result in
            switch result {
            case .success:
                callback(ctx, nil)
            case .failure(let error):
                callback(ctx, abxErrorString(error))
            }
        }
    }
}

func vmSocketDeviceCount(_ box: UnsafeMutableRawPointer) -> UInt64 {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync { UInt64(vmBox.vm.socketDevices.count) }
}

func vmSocketDeviceAt(
    _ box: UnsafeMutableRawPointer, _ index: UInt64
) -> UnsafeMutableRawPointer? {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync {
        let devices = vmBox.vm.socketDevices
        guard let device = devices[safe: Int(index)] as? VZVirtioSocketDevice else { return nil }
        return abxRetainedHandle(ABXSocketDeviceBox(device: device, queue: vmBox.queue))
    }
}

func vmBalloonCount(_ box: UnsafeMutableRawPointer) -> UInt64 {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync { UInt64(vmBox.vm.memoryBalloonDevices.count) }
}

func vmBalloonAt(_ box: UnsafeMutableRawPointer, _ index: UInt64) -> UnsafeMutableRawPointer? {
    let vmBox = abxBorrow(box, as: ABXVMBox.self)
    return vmBox.queue.sync {
        guard let device = vmBox.vm.memoryBalloonDevices[safe: Int(index)] else { return nil }
        return abxRetainedHandle(ABXBalloonBox(device: device, queue: vmBox.queue))
    }
}

func balloonTarget(_ box: UnsafeMutableRawPointer) -> UInt64 {
    let balloonBox = abxBorrow(box, as: ABXBalloonBox.self)
    return balloonBox.queue.sync {
        guard let device = balloonBox.device as? VZVirtioTraditionalMemoryBalloonDevice else {
            return 0
        }
        return device.targetVirtualMachineMemorySize
    }
}

func balloonSetTarget(_ box: UnsafeMutableRawPointer, _ bytes: UInt64) {
    let balloonBox = abxBorrow(box, as: ABXBalloonBox.self)
    balloonBox.queue.sync {
        guard let device = balloonBox.device as? VZVirtioTraditionalMemoryBalloonDevice else {
            return
        }
        device.targetVirtualMachineMemorySize = bytes
    }
}

extension Array {
    /// Bounds-checked subscript: nil instead of a trap on out-of-range.
    fileprivate subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}

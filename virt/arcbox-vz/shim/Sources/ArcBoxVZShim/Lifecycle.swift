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

/// Migration-only: wraps raw (vm, queue) ObjC pointers produced by the
/// pre-shim `build()` path. Dies once build() hands out boxes directly.
func vmBoxFromRaw(
    _ vm: UnsafeMutableRawPointer, _ queue: UnsafeMutableRawPointer
) -> UnsafeMutableRawPointer {
    abxRetainedHandle(
        ABXVMBox(
            vm: abxBorrow(vm, as: VZVirtualMachine.self),
            queue: abxBorrow(queue, as: DispatchQueue.self)))
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

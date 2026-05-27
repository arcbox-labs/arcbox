//! Grand Central Dispatch (GCD) queue handling.
//!
//! `VZVirtualMachine` requires all operations to be performed on a designated
//! dispatch queue. This module provides safe wrappers for dispatch queue operations.

use objc2::runtime::AnyObject;
use std::ffi::c_void;

// ============================================================================
// Dispatch FFI
// ============================================================================

// SAFETY: These are GCD (Grand Central Dispatch) FFI declarations from libdispatch, a system library always available on macOS.
unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> *mut AnyObject;
    fn dispatch_sync_f(
        queue: *mut AnyObject,
        context: *mut c_void,
        work: unsafe extern "C" fn(*mut c_void),
    );
    fn dispatch_async_f(
        queue: *mut AnyObject,
        context: *mut c_void,
        work: unsafe extern "C" fn(*mut c_void),
    );
    fn dispatch_release(object: *mut AnyObject);

    // Main queue is accessed via a global symbol
    static _dispatch_main_q: *mut AnyObject;
}

// ============================================================================
// Dispatch Queue
// ============================================================================

/// A wrapper around a GCD dispatch queue.
pub struct DispatchQueue {
    inner: *mut AnyObject,
    owned: bool,
}

// SAFETY: GCD dispatch queues are thread-safe by design. The inner pointer is only used to submit work via dispatch_sync_f/dispatch_async_f, which are themselves thread-safe.
unsafe impl Send for DispatchQueue {}
// SAFETY: See above — GCD queues are designed for concurrent use from multiple threads.
unsafe impl Sync for DispatchQueue {}

impl DispatchQueue {
    /// Creates a new serial dispatch queue with the given label.
    #[must_use]
    pub fn new(label: &str) -> Self {
        // Interior NUL bytes would make CString::new return Err; a panic on
        // a bad label is not worth crashing the daemon. Substitute NULs with
        // '_' so any caller-supplied label round-trips safely.
        let sanitized: String = label
            .chars()
            .map(|c| if c == '\0' { '_' } else { c })
            .collect();
        // SAFETY: `sanitized` contains no NUL bytes, so CString::new cannot fail.
        let label_cstr = std::ffi::CString::new(sanitized).expect("NULs already stripped");
        // SAFETY: dispatch_queue_create with a valid C string label and null attr (DISPATCH_QUEUE_SERIAL) always returns a valid queue.
        let queue = unsafe {
            dispatch_queue_create(
                label_cstr.as_ptr(),
                std::ptr::null(), // DISPATCH_QUEUE_SERIAL
            )
        };
        Self {
            inner: queue,
            owned: true,
        }
    }

    /// Gets the main dispatch queue.
    ///
    /// Note: The main queue is not owned and should not be released.
    #[must_use]
    pub fn main() -> Self {
        Self {
            // SAFETY: _dispatch_main_q is a global symbol always available on macOS.
            inner: unsafe { _dispatch_main_q },
            owned: false,
        }
    }

    /// Creates a wrapper around an existing queue pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure the queue pointer is valid and will remain valid
    /// for the lifetime of this wrapper.
    pub unsafe fn from_raw(ptr: *mut AnyObject) -> Self {
        Self {
            inner: ptr,
            owned: false,
        }
    }

    /// Returns the raw queue pointer.
    #[must_use]
    pub fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }

    /// Executes a closure synchronously on this queue.
    ///
    /// This function blocks until the closure completes.
    pub fn sync<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        if self.inner.is_null() {
            // No queue, execute directly
            return f();
        }

        // We need to box the closure and pass it through C
        let mut result: Option<R> = None;
        let mut closure = Some(f);

        struct Context<'a, F, R> {
            closure: &'a mut Option<F>,
            result: &'a mut Option<R>,
        }

        unsafe extern "C" fn trampoline<F, R>(context: *mut c_void)
        where
            F: FnOnce() -> R,
        {
            // SAFETY: context is a valid pointer to Context<F, R> created in sync(). The closure is taken exactly once.
            unsafe {
                let ctx = &mut *(context as *mut Context<'_, F, R>);
                if let Some(f) = ctx.closure.take() {
                    *ctx.result = Some(f());
                }
            }
        }

        let mut context = Context {
            closure: &mut closure,
            result: &mut result,
        };

        // SAFETY: Context lives on the caller's stack and dispatch_sync_f blocks until trampoline completes, so the reference remains valid.
        unsafe {
            dispatch_sync_f(
                self.inner,
                &mut context as *mut Context<'_, F, R> as *mut c_void,
                trampoline::<F, R>,
            );
        }

        result.expect("dispatch_sync_f did not execute closure")
    }

    /// Executes a closure asynchronously on this queue.
    ///
    /// This function returns immediately. The closure will be executed
    /// on the queue at some point in the future.
    pub fn async_exec<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if self.inner.is_null() {
            // No queue, execute directly
            f();
            return;
        }

        // Box the closure and leak it - it will be freed by the trampoline
        let boxed = Box::new(f);
        let context = Box::into_raw(boxed);

        unsafe extern "C" fn trampoline<F>(context: *mut c_void)
        where
            F: FnOnce() + Send + 'static,
        {
            // SAFETY: context is a valid pointer to a Box<F> leaked via Box::into_raw. We reclaim ownership here.
            unsafe {
                let f = Box::from_raw(context as *mut F);
                f();
            }
        }

        // SAFETY: context is a leaked Box pointer that will be reclaimed inside the trampoline. The trampoline has the correct type for F.
        unsafe {
            dispatch_async_f(self.inner, context as *mut c_void, trampoline::<F>);
        }
    }
}

impl Drop for DispatchQueue {
    fn drop(&mut self) {
        if self.owned && !self.inner.is_null() {
            // SAFETY: We only release queues we created (owned=true). The queue pointer was returned by dispatch_queue_create.
            unsafe {
                dispatch_release(self.inner);
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_dispatch_queue_sync() {
        let queue = DispatchQueue::new("test.queue.sync");
        let result = queue.sync(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_dispatch_queue_async() {
        let queue = DispatchQueue::new("test.queue.async");
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = flag.clone();

        queue.async_exec(move || {
            flag_clone.store(true, Ordering::SeqCst);
        });

        // Wait a bit for the async work to complete
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_main_queue() {
        let main = DispatchQueue::main();
        assert!(!main.as_ptr().is_null());
    }
}

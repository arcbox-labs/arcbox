//! Grand Central Dispatch (GCD) queue handling.
//!
//! VZVirtualMachine requires all operations to be performed on a designated
//! dispatch queue. This module provides safe wrappers for dispatch queue operations.

use objc2::runtime::AnyObject;
use std::ffi::c_void;

// ============================================================================
// Dispatch FFI
// ============================================================================

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

unsafe impl Send for DispatchQueue {}
unsafe impl Sync for DispatchQueue {}

impl DispatchQueue {
    /// Creates a new serial dispatch queue with the given label.
    pub fn new(label: &str) -> Self {
        let label_cstr = std::ffi::CString::new(label).unwrap();
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
    pub fn main() -> Self {
        Self {
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
            unsafe {
                let f = Box::from_raw(context as *mut F);
                f();
            }
        }

        unsafe {
            dispatch_async_f(self.inner, context as *mut c_void, trampoline::<F>);
        }
    }
}

impl Drop for DispatchQueue {
    fn drop(&mut self) {
        if self.owned && !self.inner.is_null() {
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

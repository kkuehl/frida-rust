/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Signals: the closures the generated `connect_*` methods hand to GLib, and the
//! [`SignalHandler`] that disconnects one.
//!
//! # Where a handler runs
//!
//! frida-core emits its signals on its own thread, the one running its main loop, not on
//! the thread that connected the handler. So a handler is `Send + 'static`: it is moved to
//! that thread, and it may keep nothing borrowed from the code that connected it. It is
//! `FnMut`, and is never run twice at once: each handler sits behind its own lock.
//!
//! A handler should not make a blocking call into frida-core (a method taking a
//! [`Cancellable`](crate::gir::Cancellable)). frida-core does answer it, by running a
//! nested main loop on its own thread while the handler waits (`src/async-task.vala`),
//! but everything else frida-core does then runs inside the handler, other handlers and
//! this handler's own signal included (this handler is skipped: it is never run twice at
//! once). Send what it needs to another thread, with a channel, and make the call there.
//! RPC calls ([`Script::call_export`](crate::gir::Script::call_export)) are refused with
//! an error on this thread, as their reply could never be delivered.
//!
//! # Arguments
//!
//! A signal's arguments are lent to the handler for the length of the emission: `&str`,
//! `&[u8]`, `&Variant` and object references (`&Device`) that the handler cannot keep.
//! To keep an object, clone it: that takes a reference of its own. Every object type
//! a signal passes is `Send` and `Sync`, so the clone may go to another thread.
//!
//! # Lifetime
//!
//! A `connect_*` method returns a [`SignalHandler`], a guard: dropping it disconnects the
//! handler, as dropping a [`MutexGuard`](std::sync::MutexGuard) unlocks. To leave the
//! handler connected for the life of the object, call [`SignalHandler::keep`].
//!
//! The closure is freed exactly once: when the handler is disconnected (by
//! [`SignalHandler::disconnect`] or by dropping the guard), or when the object it is
//! connected to is finalized, whichever comes first. If an emission is running at that
//! moment, it is freed once the emission is over. Disconnecting never blocks, so dropping
//! a guard anywhere, inside the handler itself included, cannot deadlock.
//!
//! A handler that captures a handle to the object it is connected to keeps that object
//! alive, and so itself, until it is disconnected.
//!
//! # Panics
//!
//! A panic in a handler is caught before it reaches frida-core's C frames. The handler is
//! not run again after it has panicked, as what it captured may be half-updated; the rest
//! of the program carries on. [`SignalHandler::has_panicked`] tells whether it happened.
//! The panic message goes to the panic hook, as any panic's does.

use std::cell::{RefCell, UnsafeCell};
use std::ffi::CStr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::gir::Object;

/// What GLib holds for one connected closure.
struct Handler<F> {
    f: Mutex<F>,
    panicked: Arc<AtomicBool>,
}

thread_local! {
    /// The handlers running on this thread, innermost last: a signal emitted again from
    /// inside a handler does not reach that same handler, which holds its own lock.
    static RUNNING: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Takes `id` off [`RUNNING`] when the handler returns, or unwinds.
struct RunningGuard(usize);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        RUNNING.with(|running| {
            let mut running = running.borrow_mut();
            if let Some(i) = running.iter().rposition(|&id| id == self.0) {
                running.remove(i);
            }
        });
    }
}

/// A connected signal handler, which dropping disconnects.
///
/// It does not keep the object alive: it holds a weak reference to it, so disconnecting
/// after the object is gone does nothing. [`keep`](Self::keep) leaves the handler
/// connected for the life of the object. It is `Send` and `Sync`: a handler may be
/// disconnected from any thread.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), frida::Error> {
/// use frida::DeviceManager;
///
/// let manager = DeviceManager::new()?;
/// // Connected while `added` lives.
/// let added = manager.connect_added(|device| println!("added: {}", device.name()));
/// // Connected for the life of the manager.
/// manager
///     .connect_removed(|device| println!("removed: {}", device.name()))
///     .keep();
/// drop(added); // disconnected
/// # Ok(())
/// # }
/// ```
#[must_use = "dropping a SignalHandler disconnects the handler at once; \
              call .keep() to leave it connected for the life of the object"]
pub struct SignalHandler {
    // Boxed, as a GWeakRef must not move while it is in use; in a cell, as GLib updates it.
    weak: Box<UnsafeCell<frida_sys::GWeakRef>>,
    id: frida_sys::gulong,
    panicked: Arc<AtomicBool>,
}

// SAFETY: GWeakRef is thread-safe (GLib guards it with a lock), and so are
// g_signal_handler_disconnect and g_signal_handler_is_connected; the flag is atomic.
unsafe impl Send for SignalHandler {}
// SAFETY: as for Send.
unsafe impl Sync for SignalHandler {}

impl SignalHandler {
    /// The object, if it is still alive, as a handle that owns a new reference.
    fn object(&self) -> Option<Object> {
        // SAFETY: the weak reference was initialized in `connect`, and is cleared only in
        // `drop`.
        let raw = unsafe { frida_sys::g_weak_ref_get(self.weak.get()) };
        // SAFETY: g_weak_ref_get returns a new reference, or NULL.
        unsafe { <Object as crate::gir::ObjectType>::from_glib_full(raw.cast()) }
    }

    /// Disconnects the handler, and frees the closure (after the emission running now, if
    /// one is). Returns whether it was still connected: `false` when the object has been
    /// finalized, which freed the closure already. Dropping the guard does the same.
    #[must_use]
    pub fn disconnect(self) -> bool {
        self.disconnect_now()
    }

    fn disconnect_now(&self) -> bool {
        let Some(object) = self.object() else {
            return false;
        };
        let instance = object.as_ptr().cast();
        // SAFETY: a live instance, and the id of a handler connected to it, if it still is.
        unsafe {
            if frida_sys::g_signal_handler_is_connected(instance, self.id) == 0 {
                return false;
            }
            frida_sys::g_signal_handler_disconnect(instance, self.id);
        }
        true
    }

    /// Leaves the handler connected for the life of the object, and gives up the guard.
    /// The closure is freed when the object is finalized.
    pub fn keep(self) {
        // Dropping it would disconnect; clearing the weak reference is all that is left.
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: initialized in `connect`, cleared once, here or in `drop`.
        unsafe { frida_sys::g_weak_ref_clear(this.weak.get()) };
        // SAFETY: `this` is never dropped, so the box is freed here exactly once.
        drop(unsafe { std::ptr::read(&this.weak) });
        // SAFETY: as above, for the shared flag.
        drop(unsafe { std::ptr::read(&this.panicked) });
    }

    /// Whether the handler is still connected: its object is alive and it has not been
    /// disconnected.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        // SAFETY: a live instance; the id need not be connected.
        self.object().is_some_and(|object| unsafe {
            frida_sys::g_signal_handler_is_connected(object.as_ptr().cast(), self.id) != 0
        })
    }

    /// Whether the handler has panicked, after which it is no longer run.
    #[must_use]
    pub fn has_panicked(&self) -> bool {
        self.panicked.load(Ordering::Acquire)
    }
}

impl Drop for SignalHandler {
    fn drop(&mut self) {
        self.disconnect_now();
        // SAFETY: initialized in `connect`, and cleared only here.
        unsafe { frida_sys::g_weak_ref_clear(self.weak.get()) };
    }
}

impl std::fmt::Debug for SignalHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalHandler")
            .field("id", &self.id)
            .field("connected", &self.is_connected())
            .field("panicked", &self.has_panicked())
            .finish()
    }
}

/// Frees a closure GLib no longer needs. A panic while dropping it is caught: it must not
/// unwind into GLib.
unsafe extern "C" fn free_handler<F>(
    data: frida_sys::gpointer,
    _closure: *mut frida_sys::GClosure,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the box `connect` made, which GLib frees once, through this.
        drop(unsafe { Box::from_raw(data.cast::<Handler<F>>()) })
    }));
}

/// Connects `f` to `signal` of `object`, through `trampoline`.
///
/// # Safety
///
/// `trampoline` must be an `extern "C"` function with the C signature of `signal`'s
/// handlers (the instance, the signal's arguments, then the user data), and must hand the
/// user data to [`emit::<F>`](emit). `signal` must be a signal of `object`'s type.
///
/// Should GLib not know the signal (only possible with a frida-core other than the one
/// the bindings were generated from, as the build pins it), GLib logs a critical warning,
/// the closure is dropped at once, and the handler returned is never connected:
/// [`SignalHandler::is_connected`] says so.
pub(crate) unsafe fn connect<F: Send + 'static>(
    object: &Object,
    signal: &CStr,
    trampoline: unsafe extern "C" fn(),
    f: F,
) -> SignalHandler {
    let panicked = Arc::new(AtomicBool::new(false));
    let data = Box::into_raw(Box::new(Handler {
        f: Mutex::new(f),
        panicked: panicked.clone(),
    }));
    // SAFETY: the caller promises the trampoline fits the signal; GLib owns `data` from
    // here, and frees it with `free_handler`.
    let id = unsafe {
        frida_sys::g_signal_connect_data(
            object.as_ptr().cast(),
            signal.as_ptr(),
            Some(trampoline),
            data.cast(),
            Some(free_handler::<F>),
            0,
        )
    };
    if id == 0 {
        // GLib did not take the closure, so its destroy notify will never run.
        // SAFETY: the box made above, which nothing else has.
        drop(unsafe { Box::from_raw(data) });
    }
    // SAFETY: an all-zero GWeakRef is what g_weak_ref_init expects to initialize.
    let weak = Box::new(UnsafeCell::new(unsafe {
        std::mem::zeroed::<frida_sys::GWeakRef>()
    }));
    // SAFETY: a boxed, so unmoving, weak reference to a live object.
    unsafe { frida_sys::g_weak_ref_init(weak.get(), object.as_ptr().cast()) };
    SignalHandler { weak, id, panicked }
}

/// Runs the closure behind `user_data` through `call`, which turns the C arguments into
/// Rust ones and calls it. Catches a panic, after which the closure is not run again;
/// skips a handler that is already running on this thread.
///
/// # Safety
///
/// `user_data` must be the data [`connect::<F>`](connect) gave GLib, during an emission.
pub(crate) unsafe fn emit<F>(user_data: frida_sys::gpointer, call: impl FnOnce(&mut F)) {
    // SAFETY: the caller promises the data `connect` gave GLib, alive during the emission.
    let handler = unsafe { &*user_data.cast::<Handler<F>>() };
    if handler.panicked.load(Ordering::Acquire) {
        return;
    }
    let id = user_data as usize;
    let reentered = RUNNING.with(|running| {
        let mut running = running.borrow_mut();
        if running.contains(&id) {
            true
        } else {
            running.push(id);
            false
        }
    });
    if reentered {
        return;
    }
    let _running = RunningGuard(id);
    // The lock is never poisoned, as the closure runs inside catch_unwind; take it anyway
    // if it somehow is.
    let mut f = handler
        .f
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if catch_unwind(AssertUnwindSafe(|| call(&mut f))).is_err() {
        handler.panicked.store(true, Ordering::Release);
    }
}

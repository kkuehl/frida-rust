/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! A value that is made when the first handle to it is asked for, and destroyed when the last
//! one is given back.
//!
//! This is what keeps Gum initialized exactly while a [`Gum`](crate::Gum) exists. Handles are
//! obtained and released from any thread, so when the crate is built with `--cfg loom` the lock
//! and the reference count are loom's, and its model checker runs the test below under every
//! interleaving of the threads in it.

#[cfg(all(not(loom), not(feature = "std")))]
use alloc::sync::Arc;
#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(loom))]
use spin::{Mutex, MutexGuard};
#[cfg(all(not(loom), feature = "std"))]
use std::sync::Arc;

/// A reference to the value a [`Singleton`] holds, which exists for as long as this does.
pub(crate) type Handle<T> = Arc<T>;

pub(crate) struct Singleton<T> {
    /// The value, with a reference of its own, while there are handles to it.
    slot: Mutex<Option<Arc<T>>>,
}

impl<T> Singleton<T> {
    #[cfg(not(loom))]
    pub(crate) const fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    #[cfg(loom)]
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    #[cfg(not(loom))]
    fn lock(&self) -> MutexGuard<'_, Option<Arc<T>>> {
        self.slot.lock()
    }

    #[cfg(loom)]
    fn lock(&self) -> MutexGuard<'_, Option<Arc<T>>> {
        self.slot.lock().unwrap()
    }

    /// A handle to the value, which `make` makes if there are no other handles to it.
    pub(crate) fn obtain(&self, make: impl FnOnce() -> T) -> Handle<T> {
        self.lock().get_or_insert_with(|| Arc::new(make())).clone()
    }

    /// Gives a handle back, and destroys the value if that was the last one.
    pub(crate) fn release(&self, handle: Handle<T>) {
        drop(handle);
        let mut slot = self.lock();
        // A count of one is the slot's own reference. Nothing can add to it meanwhile, as a new
        // handle is made either from another handle or from the slot, which is locked.
        let Some(last) = slot.take_if(|it| Arc::strong_count(it) == 1) else {
            return;
        };
        // The value is destroyed here, with the lock still held, so that the next one is not
        // made until this one is gone.
        Arc::try_unwrap(last)
            .ok()
            .expect("should destroy the one instance");
    }
}

#[cfg(all(test, loom))]
mod tests {
    use {
        super::*,
        loom::{
            sync::atomic::{AtomicUsize, Ordering},
            thread,
        },
    };

    /// Stands in for Gum: counts how many of it exist, from before it is made until after it is
    /// destroyed, and fails if a second one is made meanwhile.
    struct Probe {
        alive: Arc<AtomicUsize>,
    }

    impl Probe {
        fn new(alive: &Arc<AtomicUsize>) -> Self {
            let others = alive.fetch_add(1, Ordering::SeqCst);
            assert_eq!(others, 0, "made while another one exists");
            Self {
                alive: alive.clone(),
            }
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.alive.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Two threads each obtain a handle, copy it as `Gum::clone` does, and release both. The
    /// value exists whenever a thread holds a handle, there is never a second one, and none is
    /// left once every handle is released.
    #[test]
    fn value_exists_exactly_while_a_handle_does() {
        loom::model(|| {
            let singleton = Arc::new(Singleton::new());
            let alive = Arc::new(AtomicUsize::new(0));

            let spawn = || {
                let singleton = singleton.clone();
                let alive = alive.clone();
                thread::spawn(move || {
                    let handle = singleton.obtain(|| Probe::new(&alive));
                    assert_eq!(alive.load(Ordering::SeqCst), 1);
                    let copy = handle.clone();
                    singleton.release(handle);
                    assert_eq!(alive.load(Ordering::SeqCst), 1);
                    singleton.release(copy);
                })
            };
            let first = spawn();
            let second = spawn();
            first.join().unwrap();
            second.join().unwrap();

            assert_eq!(alive.load(Ordering::SeqCst), 0);
        });
    }
}

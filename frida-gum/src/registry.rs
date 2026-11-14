/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Locked snapshots of process-wide module and thread registries.
//!
//! [`ModuleRegistry`] and [`ThreadRegistry`] expose Frida's internal lookup
//! tables. Unlike [`crate::Process::enumerate_modules`] /
//! [`crate::Process::enumerate_threads`], a registry can be **locked** so
//! that successive operations observe a consistent snapshot.

use {
    crate::{
        Gum, Module, Thread, ThreadState,
        gobject::{self, InterfaceType},
    },
    core::ffi::c_void,
    cstr_core::CString,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

/// Process-wide module registry.
///
/// Calls to [`Self::lock`] / [`Self::unlock`] guarantee the snapshot
/// observed by [`Self::enumerate_modules`] is stable across invocations.
pub struct ModuleRegistry {
    inner: *mut gum_sys::GumModuleRegistry,
}

impl ModuleRegistry {
    /// Get the singleton registry instance.
    pub fn obtain() -> Self {
        ModuleRegistry {
            inner: unsafe { gum_sys::gum_module_registry_obtain() },
        }
    }

    /// Acquire the registry's read/write lock.
    ///
    /// While the lock is held, the module list cannot be modified by Frida
    /// or by other callers of [`Self::lock`].
    pub fn lock(&self) {
        unsafe { gum_sys::gum_module_registry_lock(self.inner) };
    }

    /// Release a lock previously acquired with [`Self::lock`].
    ///
    /// # Safety
    ///
    /// Must be paired one-for-one with [`Self::lock`].
    pub unsafe fn unlock(&self) {
        unsafe {
            gum_sys::gum_module_registry_unlock(self.inner);
        }
    }

    /// Run `f` while holding the registry lock.
    pub fn with_lock_held<R>(&self, f: impl FnOnce(&Self) -> R) -> R {
        self.lock();
        let result = f(self);
        unsafe { self.unlock() };
        result
    }

    /// Enumerate all modules known to the registry.
    pub fn enumerate_modules(&self) -> Vec<Module> {
        let mut result: Vec<Module> = Vec::new();

        unsafe extern "C" fn callback(
            module: *mut gum_sys::GumModule,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean {
            unsafe {
                let res = &mut *(user_data as *mut Vec<Module>);
                res.push(Module::from_raw(module));
                1
            }
        }

        unsafe {
            gum_sys::gum_module_registry_enumerate_modules(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }

        result
    }
}

unsafe impl Send for ModuleRegistry {}
unsafe impl Sync for ModuleRegistry {}

/// Tells the [`ThreadRegistry`] which threads there are, in place of what Gum has built in for
/// the system it runs on.
pub trait ThreadProvider: Send + Sync + 'static {
    /// The registry is being created. Register the threads there are with `registry`, and from
    /// now on register and unregister threads as they come and go.
    ///
    /// The registry to keep up to date later is [`ThreadRegistry::obtain`], but not here: that
    /// waits for this call to return.
    fn activate(&self, registry: &ThreadRegistry);

    /// The registry is being destroyed. Stop keeping it up to date.
    fn deactivate(&self);
}

type BoxedThreadProvider = Box<dyn ThreadProvider>;

static THREAD_PROVIDER_TYPE: InterfaceType = InterfaceType::new();

unsafe extern "C" fn thread_provider_interface_init(
    interface: gum_sys::gpointer,
    _data: gum_sys::gpointer,
) {
    let interface = unsafe { &mut *(interface as *mut gum_sys::GumThreadProviderInterface) };
    interface.activate = Some(thread_provider_activate);
    interface.deactivate = Some(thread_provider_deactivate);
}

unsafe extern "C" fn thread_provider_activate(
    provider: *mut gum_sys::GumThreadProvider,
    registry: *mut gum_sys::GumThreadRegistry,
) {
    // SAFETY: the registry holds a reference to the provider while it calls this.
    unsafe { gobject::data::<BoxedThreadProvider>(provider.cast()) }
        .activate(&ThreadRegistry { inner: registry });
}

unsafe extern "C" fn thread_provider_deactivate(provider: *mut gum_sys::GumThreadProvider) {
    // SAFETY: as above.
    unsafe { gobject::data::<BoxedThreadProvider>(provider.cast()) }.deactivate();
}

/// Process-wide thread registry.
pub struct ThreadRegistry {
    inner: *mut gum_sys::GumThreadRegistry,
}

impl ThreadRegistry {
    /// Have the registry learn about threads from `provider`, not from the system.
    ///
    /// This only has an effect before the registry is first obtained, whether by
    /// [`ThreadRegistry::obtain`] or by anything else in Gum that looks at threads. The provider
    /// is kept until Gum is torn down or another is set.
    pub fn set_provider(_gum: &Gum, provider: impl ThreadProvider) {
        let provider: BoxedThreadProvider = Box::new(provider);
        unsafe {
            let object_type = THREAD_PROVIDER_TYPE.get(
                "ThreadProvider",
                gum_sys::gum_thread_provider_get_type(),
                thread_provider_interface_init,
            );
            let provider = gobject::new_object(object_type, provider);
            gum_sys::gum_thread_registry_set_provider(provider.cast());
            // Gum holds its own reference.
            gum_sys::g_object_unref(provider as *mut c_void);
        }
    }

    /// Have the registry learn about threads from the system again. Like
    /// [`ThreadRegistry::set_provider`], this only has an effect before the registry is first
    /// obtained.
    pub fn clear_provider(_gum: &Gum) {
        unsafe { gum_sys::gum_thread_registry_set_provider(core::ptr::null_mut()) };
    }

    /// Add the thread `id` to the registry, with its name and state if they are known. Does
    /// nothing if the registry already has a thread with that ID.
    ///
    /// This is for a [`ThreadProvider`]: the registry Gum keeps for the system adds its
    /// threads itself.
    pub fn register(&self, id: usize, name: Option<&str>, state: Option<ThreadState>) {
        let name = name.and_then(|name| CString::new(name).ok());
        // SAFETY: all zeroes is a thread with nothing known about it.
        let mut details: gum_sys::GumThreadDetails = unsafe { core::mem::zeroed() };
        details.id = id as gum_sys::GumThreadId;
        if let Some(name) = &name {
            details.flags |= gum_sys::GumThreadFlags_GUM_THREAD_FLAGS_NAME;
            details.name = name.as_ptr().cast();
        }
        if let Some(state) = state {
            details.flags |= gum_sys::GumThreadFlags_GUM_THREAD_FLAGS_STATE;
            details.state = state as u32 as gum_sys::GumThreadState;
        }
        // The details are copied.
        unsafe { gum_sys::gum_thread_registry_register(self.inner, &details) };
    }

    /// Take the thread `id` out of the registry. Does nothing if it is not in it.
    pub fn unregister(&self, id: usize) {
        unsafe { gum_sys::gum_thread_registry_unregister(self.inner, id as gum_sys::GumThreadId) };
    }

    /// Give the thread `id` the name `name`, or with `None` no name. Does nothing if the thread
    /// is not in the registry.
    pub fn rename(&self, id: usize, name: Option<&str>) {
        let name = name.and_then(|name| CString::new(name).ok());
        let name = name
            .as_ref()
            .map_or(core::ptr::null(), |name| name.as_ptr().cast());
        unsafe {
            gum_sys::gum_thread_registry_rename(self.inner, id as gum_sys::GumThreadId, name)
        };
    }

    /// Get the singleton registry instance.
    pub fn obtain() -> Self {
        ThreadRegistry {
            inner: unsafe { gum_sys::gum_thread_registry_obtain() },
        }
    }

    /// Acquire the registry's lock.
    pub fn lock(&self) {
        unsafe { gum_sys::gum_thread_registry_lock(self.inner) };
    }

    /// Release the registry's lock.
    ///
    /// # Safety
    ///
    /// Must be paired one-for-one with [`Self::lock`].
    pub unsafe fn unlock(&self) {
        unsafe {
            gum_sys::gum_thread_registry_unlock(self.inner);
        }
    }

    /// Run `f` while holding the registry lock.
    pub fn with_lock_held<R>(&self, f: impl FnOnce(&Self) -> R) -> R {
        self.lock();
        let result = f(self);
        unsafe { self.unlock() };
        result
    }

    /// Enumerate all threads known to the registry.
    pub fn enumerate_threads(&self) -> Vec<Thread> {
        let mut result: Vec<Thread> = Vec::new();

        unsafe extern "C" fn callback(
            details: *const gum_sys::GumThreadDetails,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean {
            unsafe {
                let res = &mut *(user_data as *mut Vec<Thread>);
                res.push(Thread::from_raw(details));
                1
            }
        }

        unsafe {
            gum_sys::gum_thread_registry_enumerate_threads(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }

        result
    }
}

unsafe impl Send for ThreadRegistry {}
unsafe impl Sync for ThreadRegistry {}

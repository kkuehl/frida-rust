/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Resolving the modules and symbols that a module being mapped by a [`Mapper`](crate::Mapper)
//! depends on.
//!
//! Added in Frida 17.20.

use {
    crate::{Gum, Module, enumeration::string_at},
    core::{ffi::c_void, mem::MaybeUninit, ptr},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::{gchar, gpointer},
};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

/// Where a symbol is, as [`NativeModuleResolver::find_dynamic_symbol`] found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicSymbolDetails {
    pub address: u64,
    /// Whether `address` is not the symbol itself but a function to call for its address, as
    /// with an ELF indirect function.
    pub indirect: bool,
}

type LookupHandler = Box<dyn FnMut(&str) -> Option<u64>>;

unsafe extern "C" fn lookup_callout(
    symbol: *const gchar,
    user_data: gpointer,
) -> gum_sys::GumAddress {
    let handler = unsafe { &mut *(user_data as *mut LookupHandler) };
    let symbol = unsafe { string_at(symbol) }.unwrap_or_default();
    handler(&symbol).unwrap_or(0)
}

unsafe extern "C" fn lookup_destroy(user_data: gpointer) {
    drop(unsafe { Box::from_raw(user_data as *mut LookupHandler) });
}

/// Resolves modules and symbols as this process's loader would: among the modules loaded here,
/// loading a module that is not.
pub struct NativeModuleResolver {
    inner: *mut gum_sys::GumNativeModuleResolver,
}

impl NativeModuleResolver {
    pub fn new(_gum: &Gum) -> Self {
        Self {
            inner: unsafe { gum_sys::gum_native_module_resolver_new() },
        }
    }

    pub(crate) fn as_raw(&self) -> *mut gum_sys::GumModuleResolver {
        self.inner.cast()
    }

    /// Has `handler` asked for a symbol's address before the loaded modules' exports are
    /// searched for it. Where it returns `None`, they are searched as before. It replaces any
    /// earlier handler.
    pub fn set_dynamic_lookup_handler(&self, handler: impl FnMut(&str) -> Option<u64> + 'static) {
        let handler: *mut LookupHandler = Box::into_raw(Box::new(Box::new(handler)));
        unsafe {
            gum_sys::gum_native_module_resolver_set_dynamic_lookup_handler(
                self.inner,
                Some(lookup_callout),
                handler.cast(),
                Some(lookup_destroy),
            );
        }
    }

    /// Removes the handler [`NativeModuleResolver::set_dynamic_lookup_handler`] set.
    pub fn clear_dynamic_lookup_handler(&self) {
        unsafe {
            gum_sys::gum_native_module_resolver_set_dynamic_lookup_handler(
                self.inner,
                None,
                ptr::null_mut(),
                None,
            );
        }
    }

    /// The module named `name`, by name or by path, loading it if it is not loaded yet. `None`
    /// if there is no such module to load.
    pub fn find_module_by_name(&self, name: &str) -> Option<Module> {
        let name = CString::new(name).ok()?;
        let module = unsafe {
            gum_sys::gum_module_resolver_find_module_by_name(self.as_raw(), name.as_ptr().cast())
        };
        // SAFETY: the reference returned is the caller's.
        (!module.is_null()).then(|| unsafe { Module::from_owned(module) })
    }

    /// The address of `symbol`: what the lookup handler says, or else that of the export of
    /// that name in the first loaded module to have one.
    pub fn find_dynamic_address(&self, symbol: &str) -> Option<u64> {
        let symbol = CString::new(symbol).ok()?;
        let address = unsafe {
            gum_sys::gum_module_resolver_find_dynamic_address(self.as_raw(), symbol.as_ptr().cast())
        };
        (address != 0).then_some(address)
    }

    /// Like [`NativeModuleResolver::find_dynamic_address`], and says whether the address is the
    /// symbol or a function to call for it.
    pub fn find_dynamic_symbol(&self, symbol: &str) -> Option<DynamicSymbolDetails> {
        let symbol = CString::new(symbol).ok()?;
        let mut details = MaybeUninit::<gum_sys::GumDynamicSymbolDetails>::uninit();
        unsafe {
            let found = gum_sys::gum_module_resolver_find_dynamic_symbol(
                self.as_raw(),
                symbol.as_ptr().cast(),
                details.as_mut_ptr(),
            );
            if found == 0 {
                return None;
            }
            let details = details.assume_init();
            Some(DynamicSymbolDetails {
                address: details.address,
                indirect: details.indirect != 0,
            })
        }
    }
}

impl Drop for NativeModuleResolver {
    fn drop(&mut self) {
        // Destroys the lookup handler too.
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}

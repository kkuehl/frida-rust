/*
 * Copyright © 2026 Frida-rust contributors
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Bindings to the Barebone backend added in Frida 17.18.0.
//!
//! Barebone talks to a target over a debug transport (GDB stub, JTAG/SWD, or a
//! Frida kernel module). Its default configuration is normally loaded from the
//! JSON file pointed to by `FRIDA_BAREBONE_CONFIG`; the wrappers in this module
//! expose the object-level C API for callers that want to add their own device
//! at runtime.

use frida_sys::{
    _FridaBareboneConfig, _FridaBareboneConnectionConfig, _FridaBareboneDeviceOptions,
    _FridaBareboneGoldfishPipeTransportConfig, _FridaBareboneLinuxKernelConfig,
    _FridaBareboneSerialTransportConfig, _FridaBareboneVsockPipeTransportConfig,
    _FridaBareboneXnuKernelcacheConfig, GError,
};
use std::ffi::CString;

use crate::error::{string_at, take_gerror};
use crate::{Error, LinuxKernelSymbols, Result, XnuKernelcache};

/// What a `check` function left in `error`: nothing if the configuration can be used.
unsafe fn checked(error: *mut GError) -> Result<()> {
    if error.is_null() {
        return Ok(());
    }
    let (code, message) = unsafe { take_gerror(error) };
    Err(Error::BareboneConfigInvalid { code, message })
}

/// Runtime configuration for a Barebone device.
///
/// The default constructor produces an "all defaults" configuration; more
/// sophisticated setups should populate the nested config objects via the
/// `frida_barebone_config_*` C API (available on [`Self::raw_ptr`]).
pub struct BareboneConfig {
    ptr: *mut _FridaBareboneConfig,
}

impl BareboneConfig {
    /// Create a configuration with defaults for every setting.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_barebone_config_new() },
        }
    }

    /// Access the raw pointer for advanced configuration.
    pub fn raw_ptr(&self) -> *mut _FridaBareboneConfig {
        self.ptr
    }

    /// Use `connection` to reach the target's debug stub.
    pub fn set_connection(&self, connection: &BareboneConnectionConfig) {
        unsafe { frida_sys::frida_barebone_config_set_connection(self.ptr, connection.ptr) };
    }

    /// Take the target's kernel image to be the Linux kernel `image` describes.
    pub fn set_linux_kernel(&self, image: &BareboneLinuxKernelConfig) {
        unsafe { frida_sys::frida_barebone_config_set_image(self.ptr, image.ptr.cast()) };
    }

    /// Take the target's kernel image to be the XNU kernelcache `image` describes.
    pub fn set_xnu_kernelcache(&self, image: &BareboneXnuKernelcacheConfig) {
        unsafe { frida_sys::frida_barebone_config_set_image(self.ptr, image.ptr.cast()) };
    }

    /// Whether the configuration, with everything set in it, can be used.
    pub fn check(&self) -> Result<()> {
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_barebone_config_check(self.ptr, &mut error);
            checked(error)
        }
    }
}

impl Default for BareboneConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BareboneConfig {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

/// Options that control how a Barebone device presents itself.
pub struct BareboneDeviceOptions {
    pub(crate) ptr: *mut _FridaBareboneDeviceOptions,
}

impl BareboneDeviceOptions {
    /// Create an empty options object; the backend chooses defaults.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_barebone_device_options_new() },
        }
    }

    /// Set a stable device id; if left unset, one is auto-generated.
    pub fn id(self, id: &str) -> Self {
        if let Ok(cs) = CString::new(id) {
            unsafe { frida_sys::frida_barebone_device_options_set_id(self.ptr, cs.as_ptr()) };
        }
        self
    }

    /// Set the display name; if left unset, the backend's own name is used.
    pub fn name(self, name: &str) -> Self {
        if let Ok(cs) = CString::new(name) {
            unsafe { frida_sys::frida_barebone_device_options_set_name(self.ptr, cs.as_ptr()) };
        }
        self
    }
}

impl Default for BareboneDeviceOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BareboneDeviceOptions {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

/// What kind of debug stub a [`BareboneConnectionConfig`] connects to.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareboneStubFlavor {
    /// A stub that speaks the GDB remote protocol (default).
    GdbRemote = frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_GDB_REMOTE as _,
    /// Apple's Virtualization framework.
    Vz = frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VZ as _,
    /// Parallels.
    Parallels = frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_PARALLELS as _,
    /// The Android emulator.
    AndroidEmulator =
        frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_ANDROID_EMULATOR as _,
    /// VirtualBox's GDB stub.
    VirtualBox = frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VIRTUALBOX as _,
    /// VirtualBox's debug console.
    VirtualBoxConsole =
        frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VIRTUALBOX_CONSOLE as _,
}

impl BareboneStubFlavor {
    pub(crate) fn from_raw(raw: frida_sys::FridaBareboneStubFlavor) -> Self {
        match raw {
            frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VZ => Self::Vz,
            frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_PARALLELS => {
                Self::Parallels
            }
            frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_ANDROID_EMULATOR => {
                Self::AndroidEmulator
            }
            frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VIRTUALBOX => {
                Self::VirtualBox
            }
            frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VIRTUALBOX_CONSOLE => {
                Self::VirtualBoxConsole
            }
            frida_sys::FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_GDB_REMOTE => {
                Self::GdbRemote
            }
            // Every value the linked frida-core has is named above, which
            // `enum_coverage` checks against its header. The enum has no
            // variant for a value from some other version.
            _ => Self::GdbRemote,
        }
    }
}

/// How to reach the target's debug stub. By default a GDB remote stub at `127.0.0.1:3333`.
pub struct BareboneConnectionConfig {
    ptr: *mut _FridaBareboneConnectionConfig,
}

impl BareboneConnectionConfig {
    /// Create a configuration with defaults for every setting.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_barebone_connection_config_new() },
        }
    }

    /// The host the stub listens on.
    pub fn host(&self) -> Option<String> {
        unsafe {
            string_at(frida_sys::frida_barebone_connection_config_get_host(
                self.ptr,
            ))
        }
    }

    /// Set the host the stub listens on. A host with a NUL in it is ignored.
    pub fn set_host(&self, host: &str) {
        if let Ok(host) = CString::new(host) {
            unsafe {
                frida_sys::frida_barebone_connection_config_set_host(self.ptr, host.as_ptr())
            };
        }
    }

    /// The port the stub listens on.
    pub fn port(&self) -> u16 {
        unsafe { frida_sys::frida_barebone_connection_config_get_port(self.ptr) }
    }

    /// Set the port the stub listens on.
    pub fn set_port(&self, port: u16) {
        unsafe { frida_sys::frida_barebone_connection_config_set_port(self.ptr, port) };
    }

    /// The local process that hosts the stub, or zero where the stub is remote.
    pub fn pid(&self) -> u32 {
        unsafe { frida_sys::frida_barebone_connection_config_get_pid(self.ptr) }
    }

    /// Set the local process that hosts the stub, which the [`BareboneStubFlavor::Vz`] and
    /// [`BareboneStubFlavor::AndroidEmulator`] flavors need.
    pub fn set_pid(&self, pid: u32) {
        unsafe { frida_sys::frida_barebone_connection_config_set_pid(self.ptr, pid) };
    }

    /// The kind of stub.
    pub fn flavor(&self) -> BareboneStubFlavor {
        BareboneStubFlavor::from_raw(unsafe {
            frida_sys::frida_barebone_connection_config_get_flavor(self.ptr)
        })
    }

    /// Set the kind of stub.
    pub fn set_flavor(&self, flavor: BareboneStubFlavor) {
        unsafe {
            frida_sys::frida_barebone_connection_config_set_flavor(self.ptr, flavor as u32 as _)
        };
    }

    /// Whether the configuration can be used: a flavor that needs the stub's process has one.
    pub fn check(&self) -> Result<()> {
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_barebone_connection_config_check(self.ptr, &mut error);
            checked(error)
        }
    }

    /// Access the raw pointer for advanced configuration.
    pub fn raw_ptr(&self) -> *mut _FridaBareboneConnectionConfig {
        self.ptr
    }
}

impl Default for BareboneConnectionConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BareboneConnectionConfig {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

/// Defines a transport over which an agent injected into the target is reached, whose one
/// setting is a path.
macro_rules! path_transport_config {
    (
        $(#[$doc:meta])*
        $name:ident, $raw:ident, $new:ident,
        $(#[$path_doc:meta])*
        $get:ident = $raw_get:ident,
        $set:ident = $raw_set:ident
    ) => {
        $(#[$doc])*
        pub struct $name {
            ptr: *mut $raw,
        }

        impl $name {
            /// Create a configuration with nothing set.
            pub fn new() -> Self {
                Self {
                    ptr: unsafe { frida_sys::$new() },
                }
            }

            $(#[$path_doc])*
            pub fn $get(&self) -> Option<String> {
                unsafe { string_at(frida_sys::$raw_get(self.ptr)) }
            }

            /// Set that path. One with a NUL in it is ignored.
            pub fn $set(&self, path: &str) {
                if let Ok(path) = CString::new(path) {
                    unsafe { frida_sys::$raw_set(self.ptr, path.as_ptr()) };
                }
            }

            /// Whether the configuration can be used: the path is set.
            pub fn check(&self) -> Result<()> {
                let mut error: *mut GError = std::ptr::null_mut();
                unsafe {
                    frida_sys::frida_barebone_transport_config_check(self.ptr.cast(), &mut error);
                    checked(error)
                }
            }

            /// Access the raw pointer, to give to an injected agent's configuration.
            pub fn raw_ptr(&self) -> *mut $raw {
                self.ptr
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { frida_sys::frida_unref(self.ptr as _) }
            }
        }
    };
}

path_transport_config!(
    /// Reaches the agent over a serial port.
    BareboneSerialTransportConfig,
    _FridaBareboneSerialTransportConfig,
    frida_barebone_serial_transport_config_new,
    /// The serial port's path.
    path = frida_barebone_serial_transport_config_get_path,
    set_path = frida_barebone_serial_transport_config_set_path
);

path_transport_config!(
    /// Reaches the agent over a vsock that the hypervisor exposes as a UNIX socket.
    BareboneVsockPipeTransportConfig,
    _FridaBareboneVsockPipeTransportConfig,
    frida_barebone_vsock_pipe_transport_config_new,
    /// The UNIX socket Frida listens on, which the agent names in its handshake.
    socket_path = frida_barebone_vsock_pipe_transport_config_get_socket_path,
    set_socket_path = frida_barebone_vsock_pipe_transport_config_set_socket_path
);

path_transport_config!(
    /// Reaches the agent over a goldfish pipe, as the Android emulator provides.
    BareboneGoldfishPipeTransportConfig,
    _FridaBareboneGoldfishPipeTransportConfig,
    frida_barebone_goldfish_pipe_transport_config_new,
    /// The UNIX socket Frida listens on, which the agent names in its handshake.
    socket_path = frida_barebone_goldfish_pipe_transport_config_get_socket_path,
    set_socket_path = frida_barebone_goldfish_pipe_transport_config_set_socket_path
);

/// Describes the target's kernel image as a Linux kernel whose symbols are known.
pub struct BareboneLinuxKernelConfig {
    ptr: *mut _FridaBareboneLinuxKernelConfig,
}

impl BareboneLinuxKernelConfig {
    /// Create a configuration with no kernel set.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_barebone_linux_kernel_config_new() },
        }
    }

    /// The kernel's symbols, if they are set.
    pub fn kernel(&self) -> Option<LinuxKernelSymbols> {
        unsafe {
            let kernel = frida_sys::frida_barebone_linux_kernel_config_get_kernel(self.ptr);
            if kernel.is_null() {
                return None;
            }
            // The configuration keeps its reference: take one for the caller.
            frida_sys::g_object_ref(kernel.cast());
            Some(LinuxKernelSymbols::from_owned(kernel))
        }
    }

    /// Set the kernel's symbols: a [`LinuxKernelImage`](crate::LinuxKernelImage) or a
    /// [`LinuxSystemMap`](crate::LinuxSystemMap).
    pub fn set_kernel(&self, kernel: &LinuxKernelSymbols) {
        unsafe {
            frida_sys::frida_barebone_linux_kernel_config_set_kernel(self.ptr, kernel.raw_ptr())
        };
    }

    /// Whether the configuration can be used: the kernel is set.
    pub fn check(&self) -> Result<()> {
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_barebone_image_config_check(self.ptr.cast(), &mut error);
            checked(error)
        }
    }

    /// Access the raw pointer for advanced configuration.
    pub fn raw_ptr(&self) -> *mut _FridaBareboneLinuxKernelConfig {
        self.ptr
    }
}

impl Default for BareboneLinuxKernelConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BareboneLinuxKernelConfig {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

/// Describes the target's kernel image as an XNU kernelcache.
pub struct BareboneXnuKernelcacheConfig {
    ptr: *mut _FridaBareboneXnuKernelcacheConfig,
}

impl BareboneXnuKernelcacheConfig {
    /// Create a configuration with no kernelcache set.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_barebone_xnu_kernelcache_config_new() },
        }
    }

    /// The kernelcache, if it is set.
    pub fn kernelcache(&self) -> Option<XnuKernelcache> {
        unsafe {
            let kernelcache =
                frida_sys::frida_barebone_xnu_kernelcache_config_get_kernelcache(self.ptr);
            if kernelcache.is_null() {
                return None;
            }
            // The configuration keeps its reference: take one for the caller.
            frida_sys::g_object_ref(kernelcache.cast());
            Some(XnuKernelcache::from_owned(kernelcache))
        }
    }

    /// Set the kernelcache.
    pub fn set_kernelcache(&self, kernelcache: &XnuKernelcache) {
        unsafe {
            frida_sys::frida_barebone_xnu_kernelcache_config_set_kernelcache(
                self.ptr,
                kernelcache.raw_ptr(),
            )
        };
    }

    /// Whether the configuration can be used: the kernelcache is set.
    pub fn check(&self) -> Result<()> {
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_barebone_image_config_check(self.ptr.cast(), &mut error);
            checked(error)
        }
    }

    /// Access the raw pointer for advanced configuration.
    pub fn raw_ptr(&self) -> *mut _FridaBareboneXnuKernelcacheConfig {
        self.ptr
    }
}

impl Default for BareboneXnuKernelcacheConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BareboneXnuKernelcacheConfig {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

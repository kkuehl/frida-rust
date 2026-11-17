/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use thiserror::Error;

/// Custom `Error` for Frida
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to attach to a device.
    #[error("Failed to attach")]
    DeviceAttachError,

    /// Failled to lookup a device.
    #[error("Failed to lookup device")]
    DeviceLookupFailed,

    /// Failed to detach a session.
    #[error("Failed to detach the current session")]
    SessionDetachError,

    /// Failed to create a script in a session.
    #[error("Failed to create the script")]
    ScriptCreationError,

    /// Failled to load a script in a session.
    #[error("Failed to load the script")]
    LoadingFailed,

    /// Failed to unload a script in a session.
    #[error("Failed to unload the script")]
    UnloadingFailed,

    /// CString conversion failed.
    #[error("Failed to convert the string into CString")]
    CStringFailed,

    /// Failed to inject library
    #[error("Failed to inject library ({code}) {message}")]
    InjectFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to enumerate the device's processes
    #[error("Failed to enumerate processes ({code}) {message}")]
    DeviceEnumerateProcessesFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to enumerate the device manager's devices
    #[error("Failed to enumerate devices ({code}) {message}")]
    DeviceEnumerateDevicesFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to query device parameters
    #[error("Failed to query device system parameters ({code}) {message}")]
    DeviceQuerySystemParametersFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to spawn program
    #[error("Failed to spawn program ({code}) {message}")]
    SpawnFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to resume
    #[error("Failed to resume ({code}) {message}")]
    ResumeFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to kill
    #[error("Failed to kill PID ({code}) {message}")]
    KillFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Compiler build/watch failed.
    #[error("Compiler build failed ({code}) {message}")]
    CompilerBuildFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Language server start/post failed.
    #[error("Language server operation failed ({code}) {message}")]
    LanguageServerFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// A pattern could not be compiled, or data could not be decoded with it.
    #[error("Pattern operation failed ({code}) {message}")]
    PatternFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// A Barebone configuration cannot be used as it is.
    #[error("Barebone config is invalid ({code}) {message}")]
    BareboneConfigInvalid {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// A kernel image, a System.map or a kernelcache could not be read.
    #[error("Failed to read kernel ({code}) {message}")]
    KernelReadFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Received unexpected RPC message.
    #[error("Unexpected RPC message received.")]
    RpcUnexpectedMessage,

    /// RPC JavaScript Error. The RPC communication was
    /// successful but there was an error in the JavaScript side
    #[error("Error on the JavaScript side: {message}")]
    RpcJsError {
        /// Error message from JavaScript.
        message: String,
    },
}

/// Takes the code and the message out of `error`, and frees it.
///
/// # Safety
///
/// `error` must be a `GError` that the caller owns.
pub(crate) unsafe fn take_gerror(error: *mut frida_sys::GError) -> (i32, String) {
    unsafe {
        let code = (*error).code;
        let message = if (*error).message.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr((*error).message)
                .to_string_lossy()
                .into_owned()
        };
        frida_sys::g_error_free(error);
        (code, message)
    }
}

/// The text at `text`, or `None` for a null pointer.
///
/// # Safety
///
/// A non-null `text` must point at a NUL-terminated string.
pub(crate) unsafe fn string_at(text: *const std::os::raw::c_char) -> Option<String> {
    if text.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned(),
    )
}

/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! The one error type of [`crate::gir`].
//!
//! Every call that can fail returns [`Error`]: what kind of failure it was, to match on,
//! frida-core's message, and the error underneath it where there is one. The kinds are
//! frida-core's own error codes (the `Frida.Error` domain), and a few more for what is not
//! frida-core's to report: a cancelled call, an RPC export that threw, a value the bindings
//! could not pass to C, and a value frida-core handed back that its API rules out.
//!
//! ```
//! use frida::{Error, ErrorKind};
//!
//! fn describe(error: &Error) -> &'static str {
//!     match error.kind() {
//!         ErrorKind::ProcessNotFound => "no such process",
//!         ErrorKind::Cancelled => "gave up",
//!         _ => "something else",
//!     }
//! }
//! # let _ = describe;
//! ```

use std::fmt;

pub use crate::gir::generated::ErrorKind;

/// The `GIOErrorEnum` code of a cancelled call.
const G_IO_ERROR_CANCELLED: i32 = 19;

/// What went wrong in a call to [`crate::gir`].
///
/// Match on [`kind`](Self::kind); [`message`](Self::message) is frida-core's text, meant
/// for people. The type is opaque so that more can be added to it without breaking
/// callers. It converts into the crate's older [`crate::Error`], so `?` works in code
/// that uses both.
pub struct Error {
    inner: Box<Inner>,
}

struct Inner {
    kind: ErrorKind,
    message: String,
    domain: Option<(String, i32)>,
    stack: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// An error of `kind` with `message`.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            inner: Box::new(Inner {
                kind,
                message: message.into(),
                domain: None,
                stack: None,
                source: None,
            }),
        }
    }

    /// An error of `kind` with `message`, caused by `source`.
    pub fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        let mut error = Self::new(kind, message);
        error.inner.source = Some(Box::new(source));
        error
    }

    /// What kind of failure this is.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }

    /// The message, as frida-core (or the script, for [`ErrorKind::Rpc`]) wrote it.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.inner.message
    }

    /// Whether the call was cancelled through its
    /// [`Cancellable`](crate::gir::Cancellable).
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.kind == ErrorKind::Cancelled
    }

    /// The GLib error domain and code the error came with, such as
    /// `("frida-error-quark", 3)`, when it came from GLib.
    #[must_use]
    pub fn domain(&self) -> Option<(&str, i32)> {
        self.inner
            .domain
            .as_ref()
            .map(|(domain, code)| (domain.as_str(), *code))
    }

    /// For [`ErrorKind::Rpc`], the JavaScript stack of the exception, if the script sent
    /// one.
    #[must_use]
    pub fn stack(&self) -> Option<&str> {
        self.inner.stack.as_deref()
    }

    pub(crate) fn rpc(message: String, stack: Option<String>) -> Self {
        let mut error = Self::new(ErrorKind::Rpc, message);
        error.inner.stack = stack;
        error
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidArgument, message)
    }

    pub(crate) fn invalid_operation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidOperation, message)
    }

    /// frida-core handed back NULL where `function`'s declaration promises a value.
    pub(crate) fn unexpected_null(function: &str) -> Self {
        Self::new(
            ErrorKind::Unexpected,
            format!("{function} returned NULL, which its declaration rules out"),
        )
    }

    /// The error of a GError's domain, code and message.
    pub(crate) fn from_gerror(domain: String, code: i32, message: String, frida: bool) -> Self {
        let kind = if frida {
            ErrorKind::from_code(code)
        } else if domain == "g-io-error-quark" && code == G_IO_ERROR_CANCELLED {
            ErrorKind::Cancelled
        } else {
            ErrorKind::Other
        };
        let mut error = Self::new(kind, message);
        error.inner.domain = Some((domain, code));
        error
    }

    /// The error a cancelled call fails with.
    pub(crate) fn cancelled() -> Self {
        Self::from_gerror(
            "g-io-error-quark".to_string(),
            G_IO_ERROR_CANCELLED,
            "Operation was cancelled".to_string(),
            false,
        )
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Error");
        s.field("kind", &self.inner.kind)
            .field("message", &self.inner.message);
        if let Some((domain, code)) = &self.inner.domain {
            s.field("domain", domain).field("code", code);
        }
        if let Some(stack) = &self.inner.stack {
            s.field("stack", stack);
        }
        if let Some(source) = &self.inner.source {
            s.field("source", source);
        }
        s.finish()
    }
}

/// The message, or the kind's description when there is no message.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.inner.message.is_empty() {
            fmt::Display::fmt(&self.inner.kind, f)
        } else {
            f.write_str(&self.inner.message)
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner
            .source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

impl From<ErrorKind> for Error {
    /// An error of that kind, with no message.
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind, String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frida_error_has_its_kind_and_domain() {
        let error = Error::from_gerror(
            "frida-error-quark".to_string(),
            3,
            "unable to find process".to_string(),
            true,
        );
        assert_eq!(error.kind(), ErrorKind::ProcessNotFound);
        assert_eq!(error.message(), "unable to find process");
        assert_eq!(error.to_string(), "unable to find process");
        assert_eq!(error.domain(), Some(("frida-error-quark", 3)));
        assert!(!error.is_cancelled());
    }

    #[test]
    fn a_cancelled_call_is_cancelled_and_other_domains_are_other() {
        assert!(Error::cancelled().is_cancelled());
        assert_eq!(Error::cancelled().kind(), ErrorKind::Cancelled);
        let other = Error::from_gerror("g-io-error-quark".to_string(), 1, "x".to_string(), false);
        assert_eq!(other.kind(), ErrorKind::Other);
        let unknown = Error::from_gerror("frida-error-quark".to_string(), 999, String::new(), true);
        assert_eq!(unknown.kind(), ErrorKind::Other);
        assert_eq!(unknown.to_string(), ErrorKind::Other.to_string());
    }

    #[test]
    fn the_source_is_kept() {
        let nul = std::ffi::CString::new("a\0b").unwrap_err();
        let error = Error::with_source(ErrorKind::InvalidArgument, "a NUL byte", nul);
        assert!(std::error::Error::source(&error).is_some());
    }
}

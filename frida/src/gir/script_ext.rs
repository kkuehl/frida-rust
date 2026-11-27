/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Written by hand on top of the generated [`Script`]: its messages parsed, posting JSON
//! values, and RPC with its `rpc.exports`.

use serde_json::Value;

use crate::gir::{Cancellable, Error, Message, Script, SignalHandler, rpc};

impl Script {
    /// Connects `handler` to the script's messages, parsed: a [`Message`], and the binary
    /// data the script sent beside it, if any.
    ///
    /// Replies to RPC requests ([`call_export`](Self::call_export) and
    /// [`list_exports`](Self::list_exports)) are not handed to it. For every message as
    /// frida-core delivers it, use [`connect_message`](Self::connect_message).
    ///
    /// `handler` runs on frida-core's thread, as every signal handler does. Dropping the
    /// returned [`SignalHandler`] disconnects it; the [`signal`](crate::gir::signal) module
    /// has the details.
    pub fn on_message<F>(&self, mut handler: F) -> SignalHandler
    where
        F: FnMut(Message, Option<&[u8]>) + Send + 'static,
    {
        self.connect_message(move |json, data| {
            let message = Message::from_json(json);
            if !rpc::is_reply(&message) {
                handler(message, data);
            }
        })
    }

    /// Posts `message`, a JSON value, to the script, with binary data beside it if
    /// `data` is given. The script receives it with `recv()`.
    ///
    /// Unlike [`post`](Self::post), which takes JSON text, this cannot be handed a string
    /// with a NUL byte: serde_json escapes it.
    ///
    /// # Errors
    ///
    /// Only for binary data larger than GLib can hold.
    pub fn post_json(&self, message: &Value, data: Option<&[u8]>) -> Result<(), Error> {
        self.post(&message.to_string(), data)
    }

    /// The names of the script's `rpc.exports`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidOperation`](crate::gir::ErrorKind::InvalidOperation) if the
    /// script is destroyed, before or while this waits, or if this is called on
    /// frida-core's thread (from a signal handler), where the reply could never arrive;
    /// [`ErrorKind::Cancelled`](crate::gir::ErrorKind::Cancelled) if `cancellable` is
    /// cancelled; and [`ErrorKind::Protocol`](crate::gir::ErrorKind::Protocol) for a reply
    /// that is not a list of names.
    pub fn list_exports(&self, cancellable: Option<&Cancellable>) -> Result<Vec<String>, Error> {
        let (value, _) = rpc::request(self, vec![Value::from("list")], cancellable)?;
        let Value::Array(names) = value else {
            return Err(rpc::unexpected_reply());
        };
        names
            .into_iter()
            .map(|name| match name {
                Value::String(name) => Ok(name),
                _ => Err(rpc::unexpected_reply()),
            })
            .collect()
    }

    /// Calls the export `name` of the script's `rpc.exports` with `args`, and returns what
    /// it returned, or resolved to, as JSON: `Value::Null` for `undefined`.
    ///
    /// An export returning an `ArrayBuffer` sends it as binary data, which this drops:
    /// use [`call_export_with_data`](Self::call_export_with_data) for it.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Rpc`](crate::gir::ErrorKind::Rpc), with the script's message and
    /// [stack](Error::stack), if the export throws or rejects, or does not exist. The
    /// others are those of [`list_exports`](Self::list_exports).
    pub fn call_export(
        &self,
        name: &str,
        args: &[Value],
        cancellable: Option<&Cancellable>,
    ) -> Result<Value, Error> {
        self.call_export_with_data(name, args, cancellable)
            .map(|(value, _)| value)
    }

    /// As [`call_export`](Self::call_export), with the binary data the reply carries:
    /// an export that returns an `ArrayBuffer` sends its bytes this way.
    ///
    /// # Errors
    ///
    /// Those of [`call_export`](Self::call_export).
    pub fn call_export_with_data(
        &self,
        name: &str,
        args: &[Value],
        cancellable: Option<&Cancellable>,
    ) -> Result<(Value, Option<Vec<u8>>), Error> {
        rpc::request(
            self,
            vec![
                Value::from("call"),
                Value::from(name),
                Value::Array(args.to_vec()),
            ],
            cancellable,
        )
    }
}

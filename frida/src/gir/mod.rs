/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! frida-core's API, generated from the `frida-core.gir` that ships in its devkit.
//!
//! Every class, enumeration, constructor, method, property and signal frida-core
//! describes is here, generated into `src/gir/generated/`, with a few conveniences
//! written by hand beside it. The generator, `frida_rust` in this repository, reads the
//! model of the API that Frida's shared generator core, the `frida-bindgen` submodule,
//! makes, as Frida's other bindings do.
//! `scripts/update-bindings.sh` regenerates it for the release in `FRIDA_VERSION`. The
//! older hand-written types at the crate root (`frida::DeviceManager` and the rest) are
//! separate.
//!
//! # A first program
//!
//! Attach to a process on this machine, load a script, and read its messages:
//!
//! ```no_run
//! use frida::{DeviceManager, Message};
//!
//! fn main() -> Result<(), frida::Error> {
//!     let manager = DeviceManager::new()?;
//!     let device = manager.get_local_device()?;
//!     let session = device.attach(std::process::id(), None, None)?;
//!     let script = session.create_script("send({ hello: 'world' });", None, None)?;
//!
//!     let (sender, messages) = std::sync::mpsc::channel();
//!     let _handler = script.on_message(move |message, _data| {
//!         let _ = sender.send(message);
//!     });
//!     script.load(None)?;
//!
//!     if let Ok(Message::Send(send)) = messages.recv() {
//!         println!("the script sent {}", send.payload);
//!     }
//!     // Dropping `script`, `session` and `manager` unloads, detaches and closes.
//!     Ok(())
//! }
//! ```
//!
//! # The shape of the API
//!
//! - **Handles.** A class such as [`Device`] or [`Session`] is a handle: a reference to a
//!   frida-core object. Cloning one takes another reference; dropping one gives it back
//!   and releases nothing else. A class dereferences to its parent class, and converts to
//!   every ancestor with `AsRef` and `From`; [`Object::downcast`] goes the other way.
//!   Every handle is `Send` and `Sync` (see *Threads*).
//! - **Owners.** What a call acquires comes back as an [`Owned`]: dropping it releases the
//!   resource (detaches the session, unloads the script, closes the device manager), and
//!   a method of the same name does it explicitly and returns the error. The [`owned`]
//!   module lists them, and says what dropping does on which thread.
//! - **Options are values.** [`SpawnOptions`], [`SessionOptions`], [`ScriptOptions`] and
//!   the other option and configuration types are plain Rust structs, built in one
//!   expression: `SpawnOptions::new().argv(["ls", "-l"]).cwd("/tmp")`. A field left alone
//!   keeps frida-core's default. An abstract configuration, such as
//!   [`BareboneAllocatorConfig`], is an enum of its kinds.
//! - **Methods.** Where frida-core has an async method and a blocking `_sync` form, the
//!   blocking form is generated under the plain name (`Device::spawn` calls
//!   `frida_device_spawn_sync`) and takes an optional [`Cancellable`]. The async forms are
//!   a later phase.
//! - **Rust's types at the boundary.** Strings are `&str` in and `String` out; paths on
//!   this machine are `&Path` and `PathBuf`; waits are [`Duration`](std::time::Duration)s,
//!   `None` waiting for ever; an environment is name and value pairs; lists frida-core
//!   returns are `Vec`s; a `GVariant` is a [`crate::Variant`]; and a value the GIR marks
//!   nullable is an `Option`.
//! - **Enumerations** convert to and from their raw values, display as frida-core's name
//!   for them (`local`), and parse from it. A raw value with no variant is `Unknown`.
//! - **Errors.** Every call that can fail returns [`Error`], whose [`ErrorKind`] is one of
//!   frida-core's error codes, or one of the bindings' own: a cancelled call, an RPC export
//!   that threw, an argument that cannot be passed to C (a string holding a NUL byte), and
//!   a value frida-core returned that its declaration rules out. Nothing in this module
//!   panics on such input.
//! - **Callbacks** that frida-core calls during the call (predicates, `enumerate_*`) take
//!   a closure. A panic in one is caught, and raised again when the call returns.
//! - **Signals** are `connect_*` methods taking a closure, such as
//!   [`Session::connect_detached`]. They return a [`SignalHandler`], which disconnects
//!   the handler when dropped. The [`signal`] module says where handlers run.
//!
//! # Written by hand on top
//!
//! - [`Script::on_message`] hands each message parsed, as a [`Message`], with its binary
//!   data; [`Script::post_json`] posts a JSON value.
//! - [`Script::list_exports`], [`Script::call_export`] and
//!   [`Script::call_export_with_data`] call the script's `rpc.exports`. A call fails,
//!   rather than waiting for ever, once the script is destroyed, and it takes a
//!   [`Cancellable`].
//! - [`DeviceManager::get_local_device`], [`Device::enumerate_processes_with_scope`],
//!   [`Device::enumerate_applications_with_scope`],
//!   [`BareboneInjectedAgentConfig::from_file`] and [`PatternValue::value_as_f64`].
//! - [`LinuxSystemMap::from_blob`] and [`LinuxSystemMap::open`], in place of frida-core's,
//!   which read past the end of a blob that does not end in a NUL.
//! - [`Inject`], a trait over [`Device`] and [`Injector`]; and
//!   [`schedule_on_frida_thread`].
//!
//! # Threads
//!
//! Every handle is `Send` and `Sync`, and every value is plain data. frida-core runs its
//! objects on its own thread; a call made from another either goes through frida-core's
//! own hand-off (the blocking calls, and a few methods that queue their work), reads
//! state frida-core sets once, or is run on frida-core's thread by these bindings while
//! the caller waits. Signal handlers run on frida-core's thread. The evidence for each
//! class is in `src/gir/runtime.rs` and `frida_rust/customization.py`.
//!
//! # frida-core's life
//!
//! The first constructor initializes frida-core, once; nothing needs to be obtained
//! first. frida-core then runs for the
//! life of the process, as it does in frida-python and frida-node. A program that wants
//! its threads gone before exiting calls [`deinit`] once everything from this module has
//! been dropped; it refuses, with an error, while anything is still alive, and frida-core
//! cannot be initialized again afterwards. [`version`] is the version of frida-core
//! linked in.

mod barebone_ext;
mod device_ext;
mod device_manager_ext;
mod error;
mod generated;
mod gio;
mod inject;
mod kernel_ext;
pub(crate) mod marshal;
mod message;
pub mod owned;
mod pattern_ext;
mod rpc;
pub(crate) mod runtime;
mod script_ext;
pub mod signal;
#[cfg(test)]
mod tests;

pub use error::{Error, ErrorKind};
pub use generated::*;
pub use gio::{Cancellable, File, FileMonitorEvent, IoStream, SocketAddress, TlsCertificate};
pub use inject::Inject;
pub use message::{LogLevel, Message, MessageError, MessageLog, MessageSend};
pub use owned::{Owned, Release};
pub use runtime::{Object, ObjectType, deinit, schedule_on_frida_thread, version};
pub use signal::SignalHandler;

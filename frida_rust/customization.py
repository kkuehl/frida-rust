#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""What the GIR cannot say, and what is knowingly left out.

Keep this table small. Everything here is something the generator would
otherwise have to guess, and each entry says where its answer comes from:
frida-core's Vala sources (cited as file:line at the release in FRIDA_VERSION),
or what frida-python, frida-node and frida-swift settled on. The generator
fails on an entry that matches nothing, so a stale one cannot linger.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Skips.
#
# Whole kinds of construct this phase leaves for later. Every item of these
# kinds is counted and listed as skipped with the reason.
PHASE_SKIPS = {
    "virtual-method": "implementing a class or an interface from Rust is a later phase",
    "sync": "blocking form of an async method: the method's wrapper, generated under its name, calls it",
    "finish": "`_finish` half of an async form; async is a later phase",
}

# Single items the generator cannot or should not generate, keyed by their GIR
# path. The generator fails on anything it cannot generate that is not listed
# here, and on any entry here that matches nothing.
SKIPS = {
    "Frida.RpcClient":
        "internal RPC plumbing, which frida-python, frida-node and frida-swift all leave out; "
        "its try_handle_message must run on the thread of an async call, and aborts the "
        "process on malformed input (lib/base/rpc.vala:72)",
    "Frida.RpcPeer":
        "the interface RpcClient talks through, left out with it",
    "Frida.AuthenticationService.authenticate":
        "async-only method of an interface Rust code implements; a later phase",
    "Frida.WebRequestHandler.handle_request":
        "async-only method of an interface Rust code implements; a later phase",
    "Frida.BareboneInjectedAgentConfig.from_file":
        "reads the agent from a file into `image`; written by hand on the value form, in "
        "src/gir/barebone_ext.rs, as the value is built in Rust",
    "Frida.BareboneInvalidImageConfig":
        "no constructor: frida-core's placeholder for an image config that was not given, "
        "which leaving `BareboneConfig::image` unset gives",
    "Frida.LinuxSystemMap.from_blob":
        "reads the blob as a C string, past its end unless it ends in NUL "
        "(linux-kernel-image.vala:96), and splits it at the line ending of the system frida-core "
        "was built on; written by hand in src/gir/kernel_ext.rs, which ends it in NUL and adds "
        "the CR a Windows build needs",
    "Frida.LinuxSystemMap.open":
        "reads the file and goes through from_blob; written by hand in src/gir/kernel_ext.rs, "
        "for the same reasons",
    "Frida.CompilerOptions":
        "nothing takes one itself: BuildOptions and WatchOptions, which Compiler takes, carry "
        "its fields",
    "Frida.error_from_efni":
        "takes an Efni.Error, from a namespace frida-core.gir does not include",
}

# ---------------------------------------------------------------------------
# Names.

# Rust names of types that differ from the GIR's.
TYPE_RENAMES = {
    # The error domain's codes are the kinds of `frida::Error`.
    "Frida.Error": "ErrorKind",
}

# Rust names of properties and methods that differ from the GIR's, by GIR path
# (`Class:property` or `Class.method`).
MEMBER_RENAMES = {
    # `dtype` is Vala's way around the keyword `type`; frida-python, frida-node and
    # frida-swift all call it `type`, which Rust cannot use.
    "Frida.Device:dtype": "device_type",
    "Frida.PatternField:no-unique-address": "has_no_unique_address",
}

# The error domain's kinds beyond frida-core's codes: what `frida::gir` reports
# itself. (variant, description for Display, doc)
ERROR_KINDS_EXTRA = [
    ("Cancelled", "operation was cancelled",
     "The call was cancelled through its `Cancellable` (GIO's `G_IO_ERROR_CANCELLED`)."),
    ("Rpc", "an RPC export failed",
     "A script's `rpc.exports` function threw, or its promise was rejected: the message is "
     "the script's, and [`Error::stack`](crate::gir::Error::stack) has its stack."),
    ("Unexpected", "frida-core returned what its API rules out",
     "frida-core handed back something its declaration rules out, such as NULL where a value "
     "is promised. It is a bug in frida-core or in these bindings."),
    ("Other", "another kind of error",
     "An error from another GLib domain, or a code this version has no name for: "
     "[`Error::domain`](crate::gir::Error::domain) has it."),
]

# Types from other namespaces, as the hand-written handles in
# `frida/src/gir/gio.rs` and `runtime.rs`: GIR name -> (Rust type, C type).
FOREIGN_OBJECTS = {
    "GObject.Object": ("Object", "GObject"),
    "Gio.Cancellable": ("Cancellable", "GCancellable"),
    "Gio.TlsCertificate": ("TlsCertificate", "GTlsCertificate"),
    "Gio.IOStream": ("IoStream", "GIOStream"),
    "Gio.File": ("File", "GFile"),
    "Gio.SocketAddress": ("SocketAddress", "GSocketAddress"),
}

# Enumerations from other namespaces, as hand-written in `frida/src/gir/gio.rs`.
FOREIGN_ENUMS = {
    "Gio.FileMonitorEvent": ("FileMonitorEvent", "GFileMonitorEvent"),
}

# ---------------------------------------------------------------------------
# Lint allowances, each on the one item that needs it, with its reason. Keep
# this empty but for what the idiomatic alternative would make worse.
ALLOWS = {
    "Frida.PatternModule.call_function": (
        "clippy::too_many_arguments",
        "frida-core's call_function: seven distinct arguments a caller always gives, which a "
        "struct made for this one call would only rename",
    ),
}

# ---------------------------------------------------------------------------
# Rust types at the boundary.
#
# The GIR says `utf8` and `gint`; these say which are paths, durations and
# environments. Keys are `Class.method.parameter` or `Class:property`.
#
# - "path": a local filesystem path, `&Path` in and `PathBuf` out (UTF-8, as
#   frida-core takes `utf8`). Paths on a device, which may be remote, stay `&str`.
# - "timeout-ms": milliseconds, 0 not waiting and negative waiting for ever
#   (frida.vala:237-253, 3525): `Option<Duration>`, `None` for ever.
# - "seconds": a `guint` of seconds: `Duration`.
# - "interval-s": a `gint` of seconds, -1 disabling it: `Option<Duration>`,
#   `None` disabled.
# - "gfile": a `Gio.File` standing for a local path: `&Path` in, `PathBuf` out.
# - "env": `NAME=VALUE` strings: pairs, as frida-python and frida-swift take a
#   dictionary for them.
BOUNDARY_TYPES = {
    "Frida.DeviceManager.get_device_by_id.timeout": "timeout-ms",
    "Frida.DeviceManager.get_device_by_type.timeout": "timeout-ms",
    "Frida.DeviceManager.get_device.timeout": "timeout-ms",
    "Frida.DeviceManager.find_device_by_id.timeout": "timeout-ms",
    "Frida.DeviceManager.find_device_by_type.timeout": "timeout-ms",
    "Frida.DeviceManager.find_device.timeout": "timeout-ms",
    "Frida.ProcessMatchOptions:timeout": "timeout-ms",
    "Frida.SessionOptions:persist-timeout": "seconds",
    "Frida.Session:persist-timeout": "seconds",
    "Frida.RemoteDeviceOptions:keepalive-interval": "interval-s",
    "Frida.SpawnOptions:env": "env",
    "Frida.SpawnOptions:envp": "env",
    "Frida.Child:envp": "env",
    "Frida.EndpointParameters:asset-root": "gfile",
    "Frida.FileMonitor.new.path": "path",
    "Frida.FileMonitor:path": "path",
    "Frida.LanguageServer.new.project_root": "path",
    "Frida.LanguageServer:project-root": "path",
    "Frida.CompilerOptions:project-root": "path",
    "Frida.LibraryOptions:project-root": "path",
    "Frida.PatternCompileOptions:project-root": "path",
    "Frida.PackageInstallOptions:project-root": "path",
    "Frida.Compiler.build_library.output_dir": "path",
    "Frida.Compiler.watch_library.output_dir": "path",
    "Frida.Injector.inject_library_file.path": "path",
    "Frida.BinaryMetadata.from_file.path": "path",
    "Frida.LinuxKernelImage.open.path": "path",
    "Frida.XnuKernelcache.open.path": "path",
    "Frida.BareboneVsockTransportConfig:socket-path": "path",
    "Frida.BareboneVsockPipeTransportConfig:socket-path": "path",
    "Frida.BareboneGoldfishPipeTransportConfig:socket-path": "path",
    "Frida.BareboneSerialTransportConfig:path": "path",
    "Frida.BareboneUartTransportConfig:path": "path",
    "Frida.BareboneDeviceTransportConfig:path": "path",
    "Frida.BareboneSocketTransportConfig:path": "path",
}

# ---------------------------------------------------------------------------
# Option and configuration values.
#
# A class whose state the caller writes (it has a writable property) becomes a
# plain Rust value: a struct with public fields and fluent setters, built into
# a fresh frida-core object at each call that takes it. Its family (the class
# above it and those below) comes with it, an abstract class becoming an enum
# of its subclasses. These are the exceptions: classes with a writable property
# that are services, not values.
NOT_VALUES = {
    "Frida.PackageManager": "a service, with signals and blocking calls; `registry` is set on frida-core's thread",
}

# Methods of a value class that add to a collection, as `verb_noun` with the
# `enumerate_` method that reads it back, if any: the collection becomes a
# `Vec` field named after the noun. GIR method -> (field, enumerate method or None).
VALUE_COLLECTIONS = {
    "Frida.ApplicationQueryOptions.select_identifier": ("selected_identifiers", "enumerate_selected_identifiers"),
    "Frida.ProcessQueryOptions.select_pid": ("selected_pids", "enumerate_selected_pids"),
    "Frida.SessionOptions.add_linker_notifier_offset": ("linker_notifier_offsets", "enumerate_linker_notifier_offsets"),
    "Frida.CompilerOptions.add_external": ("externals", "enumerate_externals"),
    "Frida.PeerOptions.add_relay": ("relays", "enumerate_relays"),
    "Frida.BareboneTargetFunctionsAllocatorConfig.add_alloc_argument": ("alloc_arguments", "enumerate_alloc_arguments"),
    "Frida.BareboneTargetFunctionsAllocatorConfig.add_free_argument": ("free_arguments", "enumerate_free_arguments"),
    "Frida.BareboneImageConfig.add_symbol": ("symbols", "enumerate_symbols"),
    "Frida.PackageInstallOptions.add_spec": ("specs", None),
    "Frida.PackageInstallOptions.add_omit": ("omits", None),
}

# Methods of value classes the value form replaces: emptying and testing a
# collection, which the `Vec` field does.
VALUE_COLLECTION_HELPERS = {
    "has_selected_identifiers", "has_selected_pids", "clear_linker_notifier_offsets",
    "clear_externals", "clear_relays", "clear_alloc_arguments", "clear_free_arguments",
    "clear_symbols", "clear_specs", "clear_omits",
}

# ---------------------------------------------------------------------------
# Owners: what a call acquires, and how dropping its owner releases it. See
# `frida/src/gir/owned.rs`. GIR class -> (release method, calls that acquire).
#
# The release runs on frida-core's thread without waiting: the async form with
# no callback, or the plain method for a release that is not async.
#
# Left out, and why (the report and owned.rs say so too):
# - DeviceManager.add_remote_device: adding an address already added returns
#   the same Device (frida.vala:345-347), so an owner could remove a device
#   another caller added.
# - add_barebone_device: the device is shared through the manager like any
#   other; an owner removing it would end what other handles use.
# - Device.spawn: a pid, like std::process::Child, which neither kills nor
#   waits on drop; and neither resume nor kill is the obvious release.
# - enable/disable pairs (spawn gating, child gating, the debugger): one flag
#   per device connection or session that every handle shares
#   (control-service.vala:556-581), not something one value owns.
# - Compiler.watch: no public unwatch; a new watch or the compiler's disposal
#   ends it (compiler.vala:53-56, 131).
# - Device.open_channel: the GIOStream closes itself when its last reference goes.
OWNERS = {
    "Frida.DeviceManager": (
        "close",
        ["Frida.DeviceManager.new", "Frida.DeviceManager.with_nonlocal_backends_only",
         "Frida.DeviceManager.with_socket_backend_only"],
    ),
    "Frida.Session": ("detach", ["Frida.Device.attach"]),
    "Frida.Script": ("unload", ["Frida.Session.create_script", "Frida.Session.create_script_from_bytes"]),
    "Frida.PortalMembership": ("terminate", ["Frida.Session.join_portal"]),
    "Frida.Service": ("cancel", ["Frida.Device.open_service"]),
    "Frida.Injector": ("close", ["Frida.Injector.new", "Frida.Injector.new_inprocess"]),
    "Frida.ControlService": ("stop", ["Frida.ControlService.new"]),
    "Frida.PortalService": ("stop", ["Frida.PortalService.new"]),
    "Frida.LanguageServer": ("stop", ["Frida.LanguageServer.new"]),
    "Frida.FileMonitor": ("disable", ["Frida.FileMonitor.new"]),
}

# ---------------------------------------------------------------------------
# Threads.
#
# Every handle is `Send` and `Sync`, by construction: what Rust calls on it is
# either safe from any thread, or is run on frida-core's thread. The evidence,
# and the rule, are in `frida/src/gir/runtime.rs`.
#
# Calls that frida-core makes thread-safe itself need nothing: the blocking
# `_sync` forms (AsyncTask.execute posts the work to frida-core's main context
# and waits, src/async-task.vala:11-40), the getters of state set once at
# construction, and the methods below.
#
# Methods that touch state frida-core's thread also uses, with no lock: these
# are run on frida-core's thread, and wait for it.
ON_FRIDA_THREAD = {
    "Frida.LanguageServer.stop": "touches `handle` with no lock, which start writes on frida-core's thread (compiler.vala:473-494)",
    "Frida.LanguageServer.post": "reads `handle` with no lock, which start writes on frida-core's thread (compiler.vala:473-494)",
    "Frida.PortalService.add_cluster_endpoint": "mutates the list start iterates on frida-core's thread (portal-service.vala:165-205)",
    "Frida.PortalService.add_control_endpoint": "mutates the list start iterates on frida-core's thread (portal-service.vala:165-205)",
    "Frida.PackageManager.set_registry": "frida-core reads `registry` on its thread for every request (package-manager.vala:2330)",
    "Frida.WebResponse.add_header": "appends to SoupMessageHeaders, which has no lock (lib/base/socket.vala:222)",
}

# Classes whose state never changes after construction, so that their getters
# are reads of immutable memory: from the audit of frida-core's sources.
# Everything else that has getters must be listed here or in MUTABLE_GETTERS.
IMMUTABLE = {
    "Frida.Device": "id, name, icon, dtype and bus are set at construction (frida.vala:873-887)",
    "Frida.Session": "pid and persist-timeout are set at construction (frida.vala:4256)",
    "Frida.Application": "construct-only, built by from_info (frida.vala:3417-3848)",
    "Frida.Process": "construct-only, built by from_info (frida.vala:3417-3848)",
    "Frida.Spawn": "construct-only (frida.vala:3417-3848)",
    "Frida.Child": "construct-only (frida.vala:3417-3848)",
    "Frida.Crash": "construct-only (frida.vala:3417-3848)",
    "Frida.BareboneCallArgument": "construct-only (frida.vala:2768-2780)",
    "Frida.BareboneMemoryAddress": "construct-only (frida.vala:3327-3340)",
    "Frida.Package": "construct-only (package-manager.vala)",
    "Frida.PackageSearchResult": "construct-only (package-manager.vala)",
    "Frida.PackageInstallResult": "construct-only (package-manager.vala)",
    "Frida.BinaryMetadata": "construct-only (binary-metadata.vala:8-25)",
    "Frida.ControlService": "construct-only properties (control-service.vala:5-12)",
    "Frida.PortalService": "construct-only properties; `device` is cleared only in dispose (portal-service.vala:147-154)",
    "Frida.FileMonitor": "`path` is construct-only (file-monitor.vala)",
    "Frida.LanguageServer": "`project-root` is construct-only (compiler.vala:403-407)",
    "Frida.PatternModule": "set in the constructor (compiler.vala:740-765)",
    "Frida.PatternInput": "construct-only (compiler.vala)",
    "Frida.PatternType": "construct-only (compiler.vala)",
    "Frida.PatternField": "construct-only (compiler.vala)",
    "Frida.PatternTypeRef": "construct-only (compiler.vala)",
    "Frida.PatternEnumValue": "construct-only (compiler.vala)",
    "Frida.PatternBit": "construct-only (compiler.vala)",
    "Frida.PatternDiagnostic": "construct-only (compiler.vala)",
    "Frida.PatternValue": "construct-only (compiler.vala)",
    "Frida.PatternVisualizer": "construct-only (compiler.vala)",
    "Frida.PatternVisualizerArgument": "construct-only (compiler.vala)",
    "Frida.StaticAuthenticationService": "`token-hash` is construct-only (lib/base/session.vala:879-899)",
    "Frida.Relay": "construct-only (lib/base/session.vala:2580)",
    "Frida.WebRequest": "set when the request is parsed (lib/base/socket.vala:124-172)",
    "Frida.WebResponse": "`status` and `body` are construct-only (lib/base/socket.vala)",
}

# Getters of classes not in IMMUTABLE, run on frida-core's thread like the
# methods in ON_FRIDA_THREAD.
MUTABLE_GETTERS = {
    "Frida.PackageManager.get_registry": "set on frida-core's thread (see set_registry)",
}

# Plain methods (not `_sync`, not property accessors) that are safe from any
# thread, and why.
THREAD_SAFE_METHODS = {
    "Frida.Device.is_lost": "reads one word frida-core sets (frida.vala:1844)",
    "Frida.Device.override_option": "takes the lock frida-core reads the table under (frida.vala:933, 1863)",
    "Frida.Bus.is_detached": "reads one word frida-core sets (frida.vala:3878)",
    "Frida.Bus.post": "queues the message for frida-core's main context (frida.vala:3967-3979)",
    "Frida.Session.is_detached": "reads one word frida-core sets (frida.vala:4267)",
    "Frida.Script.is_destroyed": "reads one word frida-core sets",
    "Frida.Script.post": "queues the message for frida-core's main context (frida.vala:5401)",
    "Frida.Service.is_closed": "reads one word frida-core sets (frida.vala:4074)",
    "Frida.Compiler.schedule_on_frida_thread": "attaches an idle source, which GLib makes thread-safe (compiler.vala:367-371)",
    "Frida.PortalService.kick": "moves onto frida-core's thread itself (portal-service.vala:272-488)",
    "Frida.PortalService.post": "moves onto frida-core's thread itself (portal-service.vala:272-488)",
    "Frida.PortalService.narrowcast": "moves onto frida-core's thread itself (portal-service.vala:272-488)",
    "Frida.PortalService.broadcast": "moves onto frida-core's thread itself (portal-service.vala:272-488)",
    "Frida.PortalService.enumerate_tags": "moves onto frida-core's thread itself, and waits (portal-service.vala:397-414)",
    "Frida.PortalService.tag": "moves onto frida-core's thread itself (portal-service.vala:272-488)",
    "Frida.PortalService.untag": "moves onto frida-core's thread itself (portal-service.vala:272-488)",
    "Frida.PatternModule.lookup": "reads the immutable type list (compiler.vala:899)",
    "Frida.PatternValue.to_variant": "builds a new variant from immutable fields (compiler.vala:1882)",
    "Frida.PatternVisualizer.to_variant": "builds a new variant from immutable fields (compiler.vala:1975)",
    "Frida.PatternVisualizerArgument.to_variant": "builds a new variant from immutable fields (compiler.vala:2095)",
    "Frida.LinuxKernelSymbols.has_symbol": "reads the table set at construction (linux-kernel-image.vala:46-73)",
    "Frida.LinuxKernelSymbols.try_find_symbol": "reads the table set at construction (linux-kernel-image.vala:262-282)",
    "Frida.WebRequest.foreach_header": "reads headers that do not change after parsing (lib/base/socket.vala:124-172)",
    "Frida.BareboneMemoryAddress.check": "reads construct-only state (frida.vala:3327-3340)",
}

# ---------------------------------------------------------------------------
# Examples, appended to a class's docs. They need a device, so they are
# compiled but not run.
EXAMPLES = {
    "Frida.DeviceManager": """\
use frida::DeviceManager;

let manager = DeviceManager::new()?;
for device in manager.enumerate_devices(None)? {
    println!("{} ({})", device.name(), device.device_type());
}
// Dropping `manager` closes it.
""",
    "Frida.Device": """\
use frida::{DeviceManager, Scope, SpawnOptions};

let manager = DeviceManager::new()?;
let device = manager.get_local_device()?;
for process in device.enumerate_processes_with_scope(Scope::Minimal, None)? {
    println!("{} {}", process.pid(), process.name());
}
let options = SpawnOptions::new().argv(["/bin/ls", "-l"]).env([("LANG", "C")]);
let pid = device.spawn("/bin/ls", Some(&options), None)?;
device.resume(pid, None)?;
""",
    "Frida.Session": """\
use std::time::Duration;
use frida::{DeviceManager, SessionOptions};

let manager = DeviceManager::new()?;
let device = manager.get_local_device()?;
let options = SessionOptions::new().persist_timeout(Duration::from_secs(30));
let session = device.attach(std::process::id(), Some(&options), None)?;
let _detached = session.connect_detached(|reason, _crash| println!("detached: {reason}"));
// Dropping `session` detaches; `detach` does it now and reports the error.
session.detach(None)?;
""",
    "Frida.Script": """\
use frida::{DeviceManager, Message};
use serde_json::json;

let manager = DeviceManager::new()?;
let session = manager.get_local_device()?.attach(std::process::id(), None, None)?;
let script = session.create_script(
    "rpc.exports = { add: (a, b) => a + b }; recv(m => send(m));",
    None,
    None,
)?;
let _messages = script.on_message(|message, _data| {
    if let Message::Send(send) = message {
        println!("{}", send.payload);
    }
});
script.load(None)?;
script.post_json(&json!({ "hello": "world" }), None)?;
assert_eq!(script.call_export("add", &[json!(2), json!(40)], None)?, json!(42));
""",
    "Frida.SpawnOptions": """\
use frida::{SpawnOptions, Stdio};

let options = SpawnOptions::new()
    .argv(["/usr/bin/env"])
    .env([("GREETING", "hello")])
    .cwd("/tmp")
    .stdio(Stdio::Pipe);
assert_eq!(options.cwd.as_deref(), Some("/tmp"));
""",
}

# ---------------------------------------------------------------------------
# Hand-written conveniences.
#
# Methods written by hand in ordinary source files under `frida/src/gir/`, on
# top of the generated types, the way frida-swift adds its assets: GIR class ->
# (the file, the methods it adds). The generator fails if one of these names is
# also a generated method's, and links them from the class's docs.
EXTENSIONS = {
    "Frida.DeviceManager": ("device_manager_ext.rs", ["get_local_device"]),
    "Frida.Device": (
        "device_ext.rs",
        ["enumerate_processes_with_scope", "enumerate_applications_with_scope"],
    ),
    "Frida.LinuxSystemMap": ("kernel_ext.rs", ["from_blob", "open"]),
    "Frida.PatternValue": ("pattern_ext.rs", ["value_as_f64"]),
    "Frida.Script": (
        "script_ext.rs",
        ["on_message", "post_json", "list_exports", "call_export", "call_export_with_data"],
    ),
}

# ---------------------------------------------------------------------------
# Callbacks.
#
# The GLib callback types frida-core takes. Their shapes are read from GLib's GIR, of
# the same frida-core release, which the core is given; any other foreign callback
# type is refused until it is added here.
FOREIGN_CALLBACKS = {
    "GLib.Func",
    "GLib.HFunc",
    "GLib.SourceFunc",
    "GLib.DestroyNotify",
}

# What the untyped `gpointer` arguments of a GLib callback really are, per
# method. frida-core declares these in Vala as `Func<T>` and `HFunc<K, V>`,
# and the type argument does not survive into the GIR. The answers come from
# frida-core's Vala sources (lib/base/session.vala, lib/base/socket.vala,
# src/frida.vala, src/compiler/compiler.vala). Vala hands a `uint` over as
# GUINT_TO_POINTER and a `uint64?` as a pointer to the value.
CALLBACK_ARGUMENTS = {
    "Frida.ApplicationQueryOptions.enumerate_selected_identifiers": {"data": "utf8"},
    "Frida.ProcessQueryOptions.enumerate_selected_pids": {"data": "guint-in-pointer"},
    "Frida.SessionOptions.enumerate_linker_notifier_offsets": {"data": "guint-in-pointer"},
    "Frida.PeerOptions.enumerate_relays": {"data": "Frida.Relay"},
    "Frida.BareboneTargetFunctionsAllocatorConfig.enumerate_alloc_arguments": {
        "data": "Frida.BareboneCallArgument",
    },
    "Frida.BareboneTargetFunctionsAllocatorConfig.enumerate_free_arguments": {
        "data": "Frida.BareboneCallArgument",
    },
    "Frida.BareboneImageConfig.enumerate_symbols": {"key": "utf8", "value": "guint64-pointer"},
    "Frida.CompilerOptions.enumerate_externals": {"data": "utf8"},
}

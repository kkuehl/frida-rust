/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! The object handle every generated class is built on.
//!
//! # Ownership
//!
//! An [`Object`] owns exactly one reference to its GObject. `Clone` takes
//! another reference with `g_object_ref`, and `Drop` gives one back with
//! `frida_unref`, which does the last unref on frida-core's thread, as several of
//! frida-core's finalizers touch state that thread uses. Every generated class is a
//! `#[repr(transparent)]` wrapper around an `Object`, so a class value is the reference:
//! there is no lifetime parameter tying it to whatever handed it out.
//!
//! # Threads
//!
//! frida-core's objects live on its own main context, and frida-core uses them from its
//! own thread whatever the caller does: it emits their signals there, and runs the work of
//! its blocking `_sync` calls there while the caller waits. A handle is a shared
//! reference, which can be cloned and the clone sent to another thread, so for a handle
//! `Send` and `Sync` amount to the same promise: that whatever Rust can call on it is safe
//! from any thread at once, alongside frida-core's own.
//!
//! **Every handle keeps that promise**, by construction. The generator puts each thing Rust
//! can call on a class into one of these, and refuses a class with anything left over
//! (`frida_rust/customization.py` holds the tables and the evidence, from
//! frida-core's sources at the release in `FRIDA_VERSION`):
//!
//! - **A blocking `_sync` call.** `AsyncTask.execute` (`src/async-task.vala`) posts the
//!   work to frida-core's main context and waits on a condition variable; on frida-core's
//!   own thread it runs a nested main loop instead.
//! - **A getter of state set once, at construction.** frida-core's records (`Process`,
//!   `Crash`, the `Pattern*` types and the rest) and the fields of its live objects that do
//!   not change (`Device::id`, `Session::pid`) are never written again, so reading them is
//!   reading immutable memory (`IMMUTABLE`).
//! - **A method that is safe from any thread**: one that hands its work to frida-core's
//!   main context itself (`Script::post`, `Bus::post`, `PortalService::post` and the rest),
//!   takes frida-core's own lock (`Device::override_option`), or reads one word frida-core
//!   sets (`is_detached` and the like) (`THREAD_SAFE_METHODS`).
//! - **Everything else is run on frida-core's thread** by these bindings, which wait for it
//!   ([`run_on_frida_thread`]): `LanguageServer::post` and `stop`, which touch a handle
//!   frida-core's thread writes; `PortalService::add_*_endpoint`, which change a list
//!   frida-core's thread iterates; `PackageManager::set_registry`; and
//!   `WebResponse::add_header` (`ON_FRIDA_THREAD`, `MUTABLE_GETTERS`).
//!
//! The option and configuration classes, whose setters write fields with no lock, are not
//! handles at all: they are Rust values, plain data, built into a fresh frida-core object
//! for each call. frida-core keeps some of those objects after the call (a `BareboneConfig`
//! for the life of its device, `PeerOptions` for its session), and reads them on its
//! thread; nothing else can reach the object it keeps, so nothing races with it.
//!
//! [`Cancellable`](crate::gir::Cancellable), [`SocketAddress`](crate::gir::SocketAddress),
//! [`TlsCertificate`](crate::gir::TlsCertificate), [`File`](crate::gir::File) and
//! [`IoStream`](crate::gir::IoStream) are hand-written: GCancellable is documented as
//! thread-safe, the others do not change once made, and only references to an IoStream
//! can be used. [`Object`] exposes only its type.
//!
//! This is also what makes signals sound. A handler runs on frida-core's thread and is
//! lent the objects the signal passes (`&Device`, `&Crash`), which are all handles.
//!
//! What this cannot rule out is frida-core itself changing, in a later release, a field it
//! sets once today. Regenerating against a new release keeps the tables honest only if
//! they are checked again; the generator fails on any entry that no longer matches.

use std::ffi::CStr;
use std::hash::{Hash, Hasher};
use std::mem::ManuallyDrop;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::gir::Error;

// --- frida-core's life ---------------------------------------------------------

/// Where frida-core is in its life: not yet initialized, initialized, or deinitialized
/// for good. Changes only with [`LIFE`] held; read without it on the fast path.
const UNINITIALIZED: u8 = 0;
const INITIALIZED: u8 = 1;
const DEINITIALIZING: u8 = 2;
const DEINITIALIZED: u8 = 3;

static STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);

/// Serializes `frida_init` and `frida_deinit`.
static LIFE: Mutex<()> = Mutex::new(());

/// How many handles (each [`Object`]) and [`Lease`]s are alive. frida-core is not
/// deinitialized while any is: a handle used after `frida_deinit` would call into a
/// stopped runtime.
static LIVE: AtomicUsize = AtomicUsize::new(0);

fn deinitialized_error() -> Error {
    Error::invalid_operation(
        "frida-core has been deinitialized, and cannot be initialized again in this process",
    )
}

/// A promise that frida-core is initialized and stays so while the lease lives. Every
/// generated constructor and static function takes one before calling frida-core, so
/// that no object is made by a runtime that is going away.
///
/// `frida_init` is not safe to enter from two threads at once (it runs `glib_init` on
/// every call, outside its own once-guard), hence the lock for the first one.
pub(crate) struct Lease(());

impl Lease {
    /// Initializes frida-core if this is the first use, and holds it initialized.
    ///
    /// Fails with [`ErrorKind::InvalidOperation`](crate::gir::ErrorKind::InvalidOperation)
    /// once frida-core has been deinitialized ([`deinit`]), as `frida_init` cannot follow
    /// `frida_deinit` (GLib aborts).
    pub(crate) fn new() -> Result<Self, Error> {
        // Counted before the state is read: a `deinit` that has not seen this count yet
        // has not reached frida_deinit either (both use sequentially consistent order).
        LIVE.fetch_add(1, Ordering::SeqCst);
        let lease = Self(());
        if STATE.load(Ordering::SeqCst) == INITIALIZED {
            return Ok(lease);
        }
        let _life = LIFE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match STATE.load(Ordering::SeqCst) {
            UNINITIALIZED => {
                // SAFETY: the first initialization, serialized by LIFE.
                unsafe { frida_sys::frida_init() };
                STATE.store(INITIALIZED, Ordering::SeqCst);
                Ok(lease)
            }
            INITIALIZED => Ok(lease),
            _ => Err(deinitialized_error()),
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Deinitializes frida-core for the rest of the process, if nothing of [`crate::gir`] is
/// still alive.
///
/// A program that wants frida-core's threads gone before it exits may call this (most do
/// not need to). Afterwards every constructor in [`crate::gir`] fails: frida-core cannot be
/// initialized again in the same process.
///
/// # Errors
///
/// [`ErrorKind::InvalidOperation`](crate::gir::ErrorKind::InvalidOperation), leaving
/// frida-core running, while any handle, owner or signal handler from [`crate::gir`] is
/// alive: drop them first. Deinitializing when frida-core is not initialized, or already
/// deinitialized, does nothing and succeeds.
pub fn deinit() -> Result<(), Error> {
    let _life = LIFE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if STATE.load(Ordering::SeqCst) != INITIALIZED {
        return Ok(());
    }
    STATE.store(DEINITIALIZING, Ordering::SeqCst);
    let live = LIVE.load(Ordering::SeqCst);
    if live > 0 {
        STATE.store(INITIALIZED, Ordering::SeqCst);
        return Err(Error::invalid_operation(format!(
            "frida-core is still in use by {live} handles of frida::gir, so it is left running"
        )));
    }
    // SAFETY: initialized, nothing alive uses it, and nothing new can start (STATE).
    unsafe { frida_sys::frida_deinit() };
    STATE.store(DEINITIALIZED, Ordering::SeqCst);
    Ok(())
}

/// The version of the frida-core linked in, such as `17.27.4`.
#[must_use]
pub fn version() -> &'static str {
    // SAFETY: frida-core returns a static string; it needs no initialization.
    let version = unsafe { CStr::from_ptr(frida_sys::frida_version_string()) };
    version.to_str().unwrap_or_default()
}

// --- frida-core's thread -------------------------------------------------------------

/// Whether this thread is running frida-core's main loop: the thread signal handlers run
/// on.
pub(crate) fn on_frida_thread() -> bool {
    // SAFETY: frida-core is initialized while any handle exists, which every caller has.
    unsafe { frida_sys::g_main_context_is_owner(frida_sys::frida_get_main_context()) != 0 }
}

/// Attaches `callback` to frida-core's main context, to run once, then free `data` with
/// `destroy`.
///
/// # Safety
///
/// frida-core must be initialized, and `callback` and `destroy` must be sound for `data`.
unsafe fn schedule(
    callback: unsafe extern "C" fn(frida_sys::gpointer) -> frida_sys::gboolean,
    data: frida_sys::gpointer,
    destroy: unsafe extern "C" fn(frida_sys::gpointer),
) {
    // SAFETY: a new idle source, handed to the main context, which keeps it.
    unsafe {
        let source = frida_sys::g_idle_source_new();
        frida_sys::g_source_set_callback(source, Some(callback), data, Some(destroy));
        frida_sys::g_source_attach(source, frida_sys::frida_get_main_context());
        frida_sys::g_source_unref(source);
    }
}

/// What `run_on_frida_thread` hands its idle callback, and the result handed back.
struct Job<F, R> {
    f: Option<F>,
    done: Arc<(Mutex<Option<std::thread::Result<R>>>, Condvar)>,
}

/// Runs `f` on frida-core's thread and returns what it returns: directly when this is
/// that thread, else by queuing it there and waiting. For the methods frida-core expects
/// to be called on its own thread, such as `LanguageServer::post`.
///
/// A panic in `f` is raised again here.
pub(crate) fn run_on_frida_thread<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    unsafe extern "C" fn run<F: FnOnce() -> R + Send, R: Send>(
        data: frida_sys::gpointer,
    ) -> frida_sys::gboolean {
        // SAFETY: `data` is the Job below, alive until `destroy` runs.
        let job = unsafe { &mut *data.cast::<Job<F, R>>() };
        if let Some(f) = job.f.take() {
            let result = catch_unwind(AssertUnwindSafe(f));
            let (slot, ready) = &*job.done;
            *slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
            ready.notify_all();
        }
        frida_sys::G_SOURCE_REMOVE as frida_sys::gboolean
    }
    unsafe extern "C" fn destroy<F, R>(data: frida_sys::gpointer) {
        // SAFETY: the box made below, freed once, by GLib. `f` is gone by now unless the
        // source never ran, which it does while frida-core is initialized.
        drop(unsafe { Box::from_raw(data.cast::<Job<F, R>>()) });
    }

    if on_frida_thread() {
        return f();
    }
    let done = Arc::new((Mutex::new(None), Condvar::new()));
    // `F` may borrow from this frame. That is sound because this waits for it to have run
    // before returning, and the job drops `f` (by running it) before signalling.
    let job: Box<Job<F, R>> = Box::new(Job {
        f: Some(f),
        done: done.clone(),
    });
    // SAFETY: the callback and destroy notify match the job's type.
    unsafe { schedule(run::<F, R>, Box::into_raw(job).cast(), destroy::<F, R>) };
    let (slot, ready) = &*done;
    let mut result = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        if let Some(result) = result.take() {
            return match result {
                Ok(value) => value,
                Err(panic) => resume_unwind(panic),
            };
        }
        result = ready
            .wait(result)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}

/// What `schedule_on_frida_thread` hands its idle callback: the closure, and the lease
/// that keeps frida-core initialized until it has run.
struct Scheduled<F> {
    f: Option<F>,
    _lease: Lease,
}

/// Runs `f` once on frida-core's thread, soon, and returns at once. A panic in
/// `f` is caught there, as it must not unwind into frida-core, and the panic hook reports
/// it.
///
/// # Errors
///
/// [`ErrorKind::InvalidOperation`](crate::gir::ErrorKind::InvalidOperation) once
/// frida-core has been deinitialized, with [`deinit`].
pub fn schedule_on_frida_thread<F>(f: F) -> Result<(), Error>
where
    F: FnOnce() + Send + 'static,
{
    unsafe extern "C" fn run<F: FnOnce()>(data: frida_sys::gpointer) -> frida_sys::gboolean {
        // SAFETY: `data` is the Scheduled below, alive until `destroy` runs.
        let job = unsafe { &mut *data.cast::<Scheduled<F>>() };
        if let Some(f) = job.f.take() {
            let _ = catch_unwind(AssertUnwindSafe(f));
        }
        frida_sys::G_SOURCE_REMOVE as frida_sys::gboolean
    }
    unsafe extern "C" fn destroy<F>(data: frida_sys::gpointer) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: the box made below, freed once, by GLib.
            drop(unsafe { Box::from_raw(data.cast::<Scheduled<F>>()) });
        }));
    }
    let job = Box::new(Scheduled {
        f: Some(f),
        _lease: Lease::new()?,
    });
    // SAFETY: frida-core is initialized (the lease); the callbacks match the job's type.
    unsafe { schedule(run::<F>, Box::into_raw(job).cast(), destroy::<F>) };
    Ok(())
}

/// A value moved to frida-core's thread and back by [`run_on_frida_thread_raw`].
struct AssertSend<T>(T);

// SAFETY: only made by `run_on_frida_thread_raw`, whose caller vouches for the move.
unsafe impl<T> Send for AssertSend<T> {}

impl<T> AssertSend<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

/// As [`run_on_frida_thread`], for a call into frida-core whose arguments are raw
/// pointers, which are not `Send`.
///
/// # Safety
///
/// What `f` captures must be sound to use on frida-core's thread while this one waits:
/// pointers to objects and values that stay alive until this returns, as the calling
/// frame keeps them.
pub(crate) unsafe fn run_on_frida_thread_raw<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let f = AssertSend(f);
    run_on_frida_thread(move || AssertSend(f.into_inner()())).into_inner()
}

/// An object and the call that releases it, to run on frida-core's thread.
struct Release {
    object: Object,
    release: unsafe fn(*mut frida_sys::GObject),
}

/// Queues `release` of `object` on frida-core's thread and returns at once: what an
/// [`Owned`](crate::gir::Owned) does when it is dropped. The object is kept alive, and so
/// frida-core initialized, until it has run.
///
/// It never blocks, so it cannot deadlock, whatever thread it is called on: on
/// frida-core's own, inside a signal handler, the release runs after the handler returns.
pub(crate) fn release_later(object: Object, release: unsafe fn(*mut frida_sys::GObject)) {
    unsafe extern "C" fn run(data: frida_sys::gpointer) -> frida_sys::gboolean {
        // SAFETY: `data` is the Release below, alive until `destroy` runs.
        let job = unsafe { &*data.cast::<Release>() };
        // SAFETY: on frida-core's thread, with a live object of the type `release` takes.
        unsafe { (job.release)(job.object.as_ptr()) };
        frida_sys::G_SOURCE_REMOVE as frida_sys::gboolean
    }
    unsafe extern "C" fn destroy(data: frida_sys::gpointer) {
        // A panic must not unwind into GLib; dropping an Object does not panic.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: the box made below, freed once, by GLib.
            drop(unsafe { Box::from_raw(data.cast::<Release>()) })
        }));
    }
    let job = Box::into_raw(Box::new(Release { object, release }));
    // SAFETY: frida-core is initialized while the object is alive; the callbacks match.
    unsafe { schedule(run, job.cast(), destroy) };
}

/// A reference to a GObject: the base of every class in [`crate::gir`].
#[repr(transparent)]
pub struct Object(NonNull<frida_sys::GObject>);

// SAFETY: an Object's own methods read only its type, which never changes, and its
// references are atomic; the last is given back on frida-core's thread (frida_unref). What
// a downcast reaches is a class handle, which is Send and Sync on its own terms.
unsafe impl Send for Object {}
// SAFETY: as for Send.
unsafe impl Sync for Object {}

impl Object {
    /// Takes over a reference the caller owns, and counts it as alive.
    fn adopt(ptr: NonNull<frida_sys::GObject>) -> Self {
        LIVE.fetch_add(1, Ordering::SeqCst);
        Self(ptr)
    }

    /// The object's pointer. The handle still owns its reference.
    #[must_use]
    pub fn as_ptr(&self) -> *mut frida_sys::GObject {
        self.0.as_ptr()
    }

    /// The name of the object's runtime type, such as `FridaDevice`.
    #[must_use]
    pub fn type_name(&self) -> String {
        // SAFETY: a live GObject's instance starts with its class, which has its GType.
        unsafe {
            let instance = self.as_ptr().cast::<frida_sys::GTypeInstance>();
            let gtype = (*(*instance).g_class).g_type;
            let name = frida_sys::g_type_name(gtype);
            if name.is_null() {
                return String::new();
            }
            CStr::from_ptr(name).to_string_lossy().into_owned()
        }
    }

    /// Whether the object is a `T`: of that class, of a subclass, or implementing that
    /// interface.
    #[must_use]
    pub fn is<T: ObjectType>(&self) -> bool {
        // SAFETY: a live instance, and a valid GType.
        unsafe {
            frida_sys::g_type_check_instance_is_a(
                self.as_ptr().cast::<frida_sys::GTypeInstance>(),
                T::static_type(),
            ) != 0
        }
    }

    /// A new reference to the object as a `T`, if it is one.
    ///
    /// A class's methods are those of the type a call declared it as. A
    /// [`BareboneConfig::allocator`](crate::gir::BareboneConfig::allocator), say, is a
    /// [`BareboneAllocatorConfig`](crate::gir::BareboneAllocatorConfig); downcast it to reach
    /// the methods of the subclass it really is.
    #[must_use]
    pub fn downcast<T: ObjectType>(&self) -> Option<T> {
        if self.is::<T>() {
            // SAFETY: just checked to be a T.
            Some(unsafe { T::from_object_unchecked(self.clone()) })
        } else {
            None
        }
    }
}

impl Clone for Object {
    fn clone(&self) -> Self {
        // SAFETY: a live object, of which this takes one more reference.
        unsafe { frida_sys::g_object_ref(self.as_ptr().cast()) };
        Self::adopt(self.0)
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: gives back the reference this owns, on frida-core's thread, which is
        // where frida-core finalizes its objects.
        unsafe { frida_sys::frida_unref(self.as_ptr().cast()) };
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Two handles are equal when they refer to the same object.
impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Object {}

impl Hash for Object {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::fmt::Debug for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Object").field(&self.type_name()).finish()
    }
}

/// A Rust type for a GObject class or interface.
///
/// # Safety
///
/// An implementation must be a `#[repr(transparent)]` wrapper around [`Object`], whose
/// [`static_type`](Self::static_type) is the GType of every object it wraps, and whose
/// `Raw` is that type's C struct. The generated classes implement it through
/// `object_type!`, which keeps to this.
pub unsafe trait ObjectType: Clone + 'static {
    /// The C struct, such as `FridaDevice`.
    type Raw;

    /// The GType of the class or interface.
    fn static_type() -> frida_sys::GType;

    /// The handle as the base [`Object`].
    fn as_object(&self) -> &Object;

    /// The object's pointer, typed. The handle still owns its reference.
    fn as_raw(&self) -> *mut Self::Raw {
        self.as_object().as_ptr().cast()
    }

    /// Wraps an object already known to be of this type.
    ///
    /// # Safety
    ///
    /// `object` must be an instance of [`Self::static_type`].
    #[doc(hidden)]
    unsafe fn from_object_unchecked(object: Object) -> Self;

    /// Takes over a reference the caller owns (`transfer full`). `None` for a null pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be null, or an instance of this type that the caller holds a reference
    /// to, which this gives to the handle.
    unsafe fn from_glib_full(ptr: *mut Self::Raw) -> Option<Self> {
        NonNull::new(ptr.cast::<frida_sys::GObject>())
            // SAFETY: the caller promises an instance of this type, whose reference this takes.
            .map(|ptr| unsafe { Self::from_object_unchecked(Object::adopt(ptr)) })
    }

    /// Takes a new reference to an object the caller does not own (`transfer none`).
    /// `None` for a null pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be null, or a live instance of this type.
    unsafe fn from_glib_none(ptr: *mut Self::Raw) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: a live instance of this type, of which this takes a reference of its own.
        unsafe {
            frida_sys::g_object_ref(ptr.cast());
            Self::from_glib_full(ptr)
        }
    }
}

/// A handle that does not own a reference: for an object that something else keeps alive
/// for as long as the `Borrowed` is used, such as a signal's argument during the emission.
/// Dropping it gives nothing back. Cloning what it dereferences to takes a reference of
/// its own, which may then be kept.
pub(crate) struct Borrowed<T>(ManuallyDrop<T>);

impl<T> std::ops::Deref for Borrowed<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

/// The object at `ptr` as a `T`, without taking a reference. `None` for a null pointer.
///
/// # Safety
///
/// `ptr` must be null, or an instance of `T` that stays alive while the result is used.
pub(crate) unsafe fn borrow<T: ObjectType>(ptr: *mut T::Raw) -> Option<Borrowed<T>> {
    // Not counted as alive, and never dropped: it owns no reference.
    NonNull::new(ptr.cast::<frida_sys::GObject>()).map(|ptr| {
        // SAFETY: the caller promises a live T.
        Borrowed(ManuallyDrop::new(unsafe {
            T::from_object_unchecked(Object(ptr))
        }))
    })
}

// SAFETY: an Object is any GObject, whose type and C struct these are.
unsafe impl ObjectType for Object {
    type Raw = frida_sys::GObject;

    fn static_type() -> frida_sys::GType {
        // SAFETY: GObject's type function takes nothing.
        unsafe { frida_sys::g_object_get_type() }
    }

    fn as_object(&self) -> &Object {
        self
    }

    unsafe fn from_object_unchecked(object: Object) -> Self {
        object
    }
}

/// Defines a class or interface handle: the struct, [`ObjectType`], `Deref` to the
/// parent so that its methods can be called, and `AsRef` and `From` to every ancestor and
/// every implemented interface.
macro_rules! object_type {
    (
        $(#[$attr:meta])*
        pub struct $name:ident: $raw:ty = $get_type:path;
        parent: $parent:ty;
        ancestors: [$($ancestor:ty),* $(,)?];
    ) => {
        $(#[$attr])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name($crate::gir::Object);

        // SAFETY: a `#[repr(transparent)]` Object of the class `$get_type` names, whose C
        // struct is `$raw`, as the generator takes both from the GIR.
        unsafe impl $crate::gir::ObjectType for $name {
            type Raw = $raw;

            fn static_type() -> frida_sys::GType {
                // SAFETY: a GType function takes nothing.
                unsafe { $get_type() }
            }

            fn as_object(&self) -> &$crate::gir::Object {
                &self.0
            }

            unsafe fn from_object_unchecked(object: $crate::gir::Object) -> Self {
                Self(object)
            }
        }

        impl std::ops::Deref for $name {
            type Target = $parent;

            fn deref(&self) -> &$parent {
                // SAFETY: every handle is a `#[repr(transparent)]` `Object`.
                unsafe { &*std::ptr::from_ref(self).cast::<$parent>() }
            }
        }

        $(
            impl AsRef<$ancestor> for $name {
                fn as_ref(&self) -> &$ancestor {
                    // SAFETY: every handle is a `#[repr(transparent)]` `Object`.
                    unsafe { &*std::ptr::from_ref(self).cast::<$ancestor>() }
                }
            }

            impl From<$name> for $ancestor {
                fn from(value: $name) -> Self {
                    // SAFETY: an instance of a class is an instance of each of its ancestors.
                    unsafe { <$ancestor as $crate::gir::ObjectType>::from_object_unchecked(value.0) }
                }
            }
        )*
    };
}

pub(crate) use object_type;

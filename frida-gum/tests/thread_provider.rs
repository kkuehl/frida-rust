//! Test for [`ThreadRegistry::set_provider`]. A provider replaces where the whole process's
//! registry gets its threads, and only before the registry exists, so this is the only test in
//! its binary.

use frida_gum::{Gum, ThreadProvider, ThreadRegistry, ThreadState};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Registers two threads when the registry is created, and counts how often it is asked to.
struct TwoThreads {
    activations: Arc<AtomicUsize>,
}

impl ThreadProvider for TwoThreads {
    fn activate(&self, registry: &ThreadRegistry) {
        self.activations.fetch_add(1, Ordering::SeqCst);
        registry.register(1001, Some("alpha"), Some(ThreadState::Waiting));
        registry.register(1002, Some("beta"), None);
    }

    fn deactivate(&self) {}
}

fn threads(registry: &ThreadRegistry) -> Vec<(usize, String)> {
    registry
        .enumerate_threads()
        .iter()
        .map(|thread| {
            (
                thread.id() as usize,
                thread.name().to_string_lossy().into_owned(),
            )
        })
        .collect()
}

#[test]
fn the_registry_holds_the_threads_its_provider_registers() {
    let gum = Gum::obtain();
    let activations = Arc::new(AtomicUsize::new(0));
    ThreadRegistry::set_provider(
        &gum,
        TwoThreads {
            activations: Arc::clone(&activations),
        },
    );

    let registry = ThreadRegistry::obtain();
    let provided = threads(&registry);
    let state_of_alpha = registry
        .enumerate_threads()
        .first()
        .map(|thread| format!("{:?}", thread.state()));
    registry.register(1001, Some("ignored: already registered"), None);
    registry.register(1003, Some("gamma"), None);
    registry.rename(1002, Some("renamed"));
    registry.rename(4242, Some("not registered"));
    registry.unregister(1001);
    registry.unregister(4242);
    let updated = threads(&registry);
    let _again = ThreadRegistry::obtain();

    assert_eq!(
        provided,
        [(1001, "alpha".to_owned()), (1002, "beta".to_owned())]
    );
    assert_eq!(state_of_alpha.as_deref(), Some("Waiting"));
    assert_eq!(
        updated,
        [(1002, "renamed".to_owned()), (1003, "gamma".to_owned())]
    );
    assert_eq!(
        activations.load(Ordering::SeqCst),
        1,
        "the provider is activated once, when the registry is created"
    );
}

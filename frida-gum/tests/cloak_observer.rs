//! Tests for [`Cloak::add_observer`]. They cloak thread IDs that no thread has, and look only
//! at what is observed about those.

use frida_gum::{Cloak, CloakObserver, Gum};
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};

lazy_static! {
    static ref GUM: Gum = Gum::obtain();
}

/// Held by each test while it runs. The cloak keeps an observer alive while it is telling the
/// observers of a change, so one test cloaking a thread would put off the destruction that
/// another is checking for.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Seen {
    Added(usize),
    Removed(usize),
}

/// Records what it is told about the threads it was made to watch.
struct Recorder {
    watched: [usize; 2],
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl CloakObserver for Recorder {
    fn thread_added(&self, id: usize) {
        if self.watched.contains(&id) {
            self.seen.lock().unwrap().push(Seen::Added(id));
        }
    }

    fn thread_removed(&self, id: usize) {
        if self.watched.contains(&id) {
            self.seen.lock().unwrap().push(Seen::Removed(id));
        }
    }
}

#[test]
fn an_observer_is_told_of_threads_cloaked_and_uncloaked_until_it_is_dropped() {
    let _gum = &*GUM;
    let _alone = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (first, second) = (0x7ff0_0001, 0x7ff0_0002);
    let seen = Arc::new(Mutex::new(Vec::new()));

    let registration = Cloak::add_observer(Recorder {
        watched: [first, second],
        seen: Arc::clone(&seen),
    });
    Cloak::add_thread(first);
    Cloak::add_thread(second);
    Cloak::remove_thread(first);
    drop(registration);
    Cloak::remove_thread(second);

    assert_eq!(
        *seen.lock().unwrap(),
        [
            Seen::Added(first),
            Seen::Added(second),
            Seen::Removed(first)
        ]
    );
    assert_eq!(
        Arc::strong_count(&seen),
        1,
        "dropping the registration destroys the observer"
    );
}

#[test]
fn every_observer_is_told() {
    let _gum = &*GUM;
    let _alone = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let thread = 0x7ff0_0003;
    let seen_by_one = Arc::new(Mutex::new(Vec::new()));
    let seen_by_other = Arc::new(Mutex::new(Vec::new()));

    let _one = Cloak::add_observer(Recorder {
        watched: [thread, thread],
        seen: Arc::clone(&seen_by_one),
    });
    let _other = Cloak::add_observer(Recorder {
        watched: [thread, thread],
        seen: Arc::clone(&seen_by_other),
    });
    Cloak::add_thread(thread);
    Cloak::remove_thread(thread);

    let expected = [Seen::Added(thread), Seen::Removed(thread)];
    assert_eq!(*seen_by_one.lock().unwrap(), expected);
    assert_eq!(*seen_by_other.lock().unwrap(), expected);
}

//! Live test of [`Stalker`] following the test's own thread.

use frida_gum::{
    Gum,
    stalker::{Stalker, Transformer},
};
use std::{cell::RefCell, hint::black_box};

#[test]
fn reserves_a_register_for_user_data_while_following_a_thread() {
    let gum = Gum::obtain();
    if !Stalker::is_supported(&gum) {
        return;
    }
    let mut stalker = Stalker::new(&gum);
    let registers = RefCell::new(Vec::new());
    let transformer = Transformer::from_callback(&gum, |basic_block, _output| {
        for instruction in basic_block {
            registers.borrow_mut().push(instruction.user_data_reg());
            instruction.keep();
        }
    });

    #[cfg(feature = "event-sink")]
    stalker.follow_me::<frida_gum::stalker::NoneEventSink>(&transformer, None);
    #[cfg(not(feature = "event-sink"))]
    stalker.follow_me(&transformer);
    let sum = (0..1000u64).fold(0, |sum, i| black_box(sum + i));
    stalker.unfollow_me();

    drop(transformer);
    let registers = registers.into_inner();
    assert_eq!(
        sum, 499_500,
        "the followed code computed what it would have"
    );
    assert!(!registers.is_empty(), "the transformer saw instructions");
    assert!(
        registers.iter().all(|register| *register != 0),
        "every instruction had a register to spare"
    );
}

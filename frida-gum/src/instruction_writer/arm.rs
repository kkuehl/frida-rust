mod register;
pub use register::*;

mod relocator;
pub use relocator::*;

mod writer;
pub use writer::*;

#[cfg(target_arch = "arm")]
mod thumb_condition;
#[cfg(target_arch = "arm")]
pub use thumb_condition::*;

#[cfg(target_arch = "arm")]
mod thumb_writer;
#[cfg(target_arch = "arm")]
pub use thumb_writer::*;

pub type TargetInstructionWriter = ArmInstructionWriter;
pub type TargetRelocator = ArmRelocator;
pub type TargetRegister = ArmRegister;

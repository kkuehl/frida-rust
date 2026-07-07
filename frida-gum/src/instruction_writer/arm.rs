mod register;
pub use register::*;

mod relocator;
pub use relocator::*;

mod writer;
pub use writer::*;

#[cfg(target_arch = "arm")]
pub mod thumb;
#[cfg(target_arch = "arm")]
pub use thumb::*;

pub type TargetInstructionWriter = ArmInstructionWriter;
pub type TargetRelocator = ArmRelocator;
pub type TargetRegister = ArmRegister;

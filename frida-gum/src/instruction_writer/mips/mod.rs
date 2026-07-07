/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

mod register;
pub use register::*;

mod writer;
pub use writer::*;

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
pub type TargetInstructionWriter = MipsInstructionWriter;
#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
pub type TargetRegister = MipsRegister;

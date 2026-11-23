// Copyright © 2026 Kirby Kuehl
//
// Licence: wxWindows Library Licence, Version 3.1

use frida_gum_sys as gum_sys;

/// ARM condition codes for conditional branch instructions.
#[derive(FromPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u32)]
pub enum ArmConditionCode {
    Invalid = gum_sys::arm_cc_ARM_CC_INVALID,
    /// Equal
    Eq = gum_sys::arm_cc_ARM_CC_EQ,
    /// Not equal
    Ne = gum_sys::arm_cc_ARM_CC_NE,
    /// Unsigned higher or same (carry set)
    Hs = gum_sys::arm_cc_ARM_CC_HS,
    /// Unsigned lower (carry clear)
    Lo = gum_sys::arm_cc_ARM_CC_LO,
    /// Negative (minus)
    Mi = gum_sys::arm_cc_ARM_CC_MI,
    /// Positive or zero (plus)
    Pl = gum_sys::arm_cc_ARM_CC_PL,
    /// Overflow set
    Vs = gum_sys::arm_cc_ARM_CC_VS,
    /// Overflow clear
    Vc = gum_sys::arm_cc_ARM_CC_VC,
    /// Unsigned higher
    Hi = gum_sys::arm_cc_ARM_CC_HI,
    /// Unsigned lower or same
    Ls = gum_sys::arm_cc_ARM_CC_LS,
    /// Signed greater than or equal
    Ge = gum_sys::arm_cc_ARM_CC_GE,
    /// Signed less than
    Lt = gum_sys::arm_cc_ARM_CC_LT,
    /// Signed greater than
    Gt = gum_sys::arm_cc_ARM_CC_GT,
    /// Signed less than or equal
    Le = gum_sys::arm_cc_ARM_CC_LE,
    /// Always (unconditional)
    Al = gum_sys::arm_cc_ARM_CC_AL,
}

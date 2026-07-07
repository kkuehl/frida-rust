/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_gum_sys as gum_sys;

#[derive(FromPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u32)]
pub enum MipsRegister {
    Invalid = gum_sys::mips_reg_MIPS_REG_INVALID as u32,
    Pc = gum_sys::mips_reg_MIPS_REG_PC as u32,

    // General purpose registers
    R0 = gum_sys::mips_reg_MIPS_REG_0 as u32,
    R1 = gum_sys::mips_reg_MIPS_REG_1 as u32,
    R2 = gum_sys::mips_reg_MIPS_REG_2 as u32,
    R3 = gum_sys::mips_reg_MIPS_REG_3 as u32,
    R4 = gum_sys::mips_reg_MIPS_REG_4 as u32,
    R5 = gum_sys::mips_reg_MIPS_REG_5 as u32,
    R6 = gum_sys::mips_reg_MIPS_REG_6 as u32,
    R7 = gum_sys::mips_reg_MIPS_REG_7 as u32,
    R8 = gum_sys::mips_reg_MIPS_REG_8 as u32,
    R9 = gum_sys::mips_reg_MIPS_REG_9 as u32,
    R10 = gum_sys::mips_reg_MIPS_REG_10 as u32,
    R11 = gum_sys::mips_reg_MIPS_REG_11 as u32,
    R12 = gum_sys::mips_reg_MIPS_REG_12 as u32,
    R13 = gum_sys::mips_reg_MIPS_REG_13 as u32,
    R14 = gum_sys::mips_reg_MIPS_REG_14 as u32,
    R15 = gum_sys::mips_reg_MIPS_REG_15 as u32,
    R16 = gum_sys::mips_reg_MIPS_REG_16 as u32,
    R17 = gum_sys::mips_reg_MIPS_REG_17 as u32,
    R18 = gum_sys::mips_reg_MIPS_REG_18 as u32,
    R19 = gum_sys::mips_reg_MIPS_REG_19 as u32,
    R20 = gum_sys::mips_reg_MIPS_REG_20 as u32,
    R21 = gum_sys::mips_reg_MIPS_REG_21 as u32,
    R22 = gum_sys::mips_reg_MIPS_REG_22 as u32,
    R23 = gum_sys::mips_reg_MIPS_REG_23 as u32,
    R24 = gum_sys::mips_reg_MIPS_REG_24 as u32,
    R25 = gum_sys::mips_reg_MIPS_REG_25 as u32,
    R26 = gum_sys::mips_reg_MIPS_REG_26 as u32,
    R27 = gum_sys::mips_reg_MIPS_REG_27 as u32,
    R28 = gum_sys::mips_reg_MIPS_REG_28 as u32,
    R29 = gum_sys::mips_reg_MIPS_REG_29 as u32,
    R30 = gum_sys::mips_reg_MIPS_REG_30 as u32,
    R31 = gum_sys::mips_reg_MIPS_REG_31 as u32,

    // Common register aliases
    Zero = gum_sys::mips_reg_MIPS_REG_ZERO as u32,
    At = gum_sys::mips_reg_MIPS_REG_AT as u32,
    V0 = gum_sys::mips_reg_MIPS_REG_V0 as u32,
    V1 = gum_sys::mips_reg_MIPS_REG_V1 as u32,
    A0 = gum_sys::mips_reg_MIPS_REG_A0 as u32,
    A1 = gum_sys::mips_reg_MIPS_REG_A1 as u32,
    A2 = gum_sys::mips_reg_MIPS_REG_A2 as u32,
    A3 = gum_sys::mips_reg_MIPS_REG_A3 as u32,
    T0 = gum_sys::mips_reg_MIPS_REG_T0 as u32,
    T1 = gum_sys::mips_reg_MIPS_REG_T1 as u32,
    T2 = gum_sys::mips_reg_MIPS_REG_T2 as u32,
    T3 = gum_sys::mips_reg_MIPS_REG_T3 as u32,
    T4 = gum_sys::mips_reg_MIPS_REG_T4 as u32,
    T5 = gum_sys::mips_reg_MIPS_REG_T5 as u32,
    T6 = gum_sys::mips_reg_MIPS_REG_T6 as u32,
    T7 = gum_sys::mips_reg_MIPS_REG_T7 as u32,
    S0 = gum_sys::mips_reg_MIPS_REG_S0 as u32,
    S1 = gum_sys::mips_reg_MIPS_REG_S1 as u32,
    S2 = gum_sys::mips_reg_MIPS_REG_S2 as u32,
    S3 = gum_sys::mips_reg_MIPS_REG_S3 as u32,
    S4 = gum_sys::mips_reg_MIPS_REG_S4 as u32,
    S5 = gum_sys::mips_reg_MIPS_REG_S5 as u32,
    S6 = gum_sys::mips_reg_MIPS_REG_S6 as u32,
    S7 = gum_sys::mips_reg_MIPS_REG_S7 as u32,
    T8 = gum_sys::mips_reg_MIPS_REG_T8 as u32,
    T9 = gum_sys::mips_reg_MIPS_REG_T9 as u32,
    K0 = gum_sys::mips_reg_MIPS_REG_K0 as u32,
    K1 = gum_sys::mips_reg_MIPS_REG_K1 as u32,
    Gp = gum_sys::mips_reg_MIPS_REG_GP as u32,
    Sp = gum_sys::mips_reg_MIPS_REG_SP as u32,
    Fp = gum_sys::mips_reg_MIPS_REG_FP as u32,
    S8 = gum_sys::mips_reg_MIPS_REG_S8 as u32,
    Ra = gum_sys::mips_reg_MIPS_REG_RA as u32,

    // Special registers
    Hi = gum_sys::mips_reg_MIPS_REG_HI as u32,
    Lo = gum_sys::mips_reg_MIPS_REG_LO as u32,
}

// Copyright © 2026 Kirby Kuehl
//
// Licence: wxWindows Library Licence, Version 3.1

use {
    crate::{
        NativePointer,
        instruction_writer::{Argument, ArmConditionCode, ArmRegister, InstructionWriter},
    },
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
    gum_sys::{GumArgument, arm_reg, gsize, gssize},
};

#[cfg(not(any(
    feature = "module-names",
    feature = "backtrace",
    feature = "memory-access-monitor"
)))]
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The ARM Thumb instruction writer.
///
/// Provides a safe Rust wrapper around Frida's Thumb instruction writer,
/// which generates ARM Thumb (16-bit/32-bit mixed) instruction sequences.
#[cfg(target_arch = "arm")]
pub struct ThumbWriter {
    pub(crate) writer: *mut gum_sys::_GumThumbWriter,
    is_from_new: bool,
}

#[cfg(target_arch = "arm")]
impl InstructionWriter for ThumbWriter {
    fn new(code_address: u64) -> Self {
        Self {
            writer: unsafe { gum_sys::gum_thumb_writer_new(code_address as *mut c_void) },
            is_from_new: true,
        }
    }

    fn code_offset(&self) -> u64 {
        unsafe { (*self.writer).code as u64 }
    }

    fn pc(&self) -> u64 {
        unsafe { (*self.writer).pc }
    }

    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_can_branch_directly_between(self.writer, source, target) != 0
        }
    }

    fn put_bytes(&self, bytes: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32)
                != 0
        }
    }

    fn put_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_thumb_writer_put_label(self.writer, id as *const c_void) != 0 }
    }

    fn reset(&self, code_address: u64) {
        unsafe { gum_sys::gum_thumb_writer_reset(self.writer, code_address as *mut c_void) }
    }

    fn put_branch_address(&self, address: u64) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_branch_address(self.writer, address);
            true
        }
    }

    fn put_nop(&self) {
        unsafe { gum_sys::gum_thumb_writer_put_nop(self.writer) }
    }

    fn flush(&self) -> bool {
        unsafe { gum_sys::gum_thumb_writer_flush(self.writer) != 0 }
    }
}

#[cfg(target_arch = "arm")]
impl ThumbWriter {
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumThumbWriter) -> Self {
        Self {
            writer,
            is_from_new: false,
        }
    }

    /// Get the underlying Frida gum writer object.
    pub fn raw_writer(&self) -> *mut gum_sys::_GumThumbWriter {
        self.writer
    }

    /// Clear (free) the writer's internal state without deallocating the writer struct itself.
    pub fn clear(&self) {
        unsafe { gum_sys::gum_thumb_writer_clear(self.writer) }
    }

    /// Get a pointer to the writer's current write cursor.
    pub fn cur(&self) -> NativePointer {
        NativePointer(unsafe { gum_sys::gum_thumb_writer_cur(self.writer) })
    }

    /// Get the writer's byte offset from the original code address.
    pub fn offset(&self) -> u32 {
        unsafe { gum_sys::gum_thumb_writer_offset(self.writer) }
    }

    /// Set the target operating system.
    pub fn set_target_os(&self, os: gum_sys::GumOS) {
        unsafe { gum_sys::gum_thumb_writer_set_target_os(self.writer, os) }
    }

    /// Skip a number of bytes in the output stream.
    pub fn skip(&self, n_bytes: u32) {
        unsafe { gum_sys::gum_thumb_writer_skip(self.writer, n_bytes) }
    }

    /// Commit a label at the current position.
    pub fn commit_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_thumb_writer_commit_label(self.writer, id as *const c_void) != 0 }
    }

    /// Insert a call to an address with arguments.
    pub fn put_call_address_with_arguments(&self, func: u64, arguments: &[Argument]) {
        let gum_arguments = Self::convert_arguments(arguments);
        unsafe {
            gum_sys::gum_thumb_writer_put_call_address_with_arguments_array(
                self.writer,
                func,
                gum_arguments.len() as u32,
                gum_arguments.as_ptr(),
            )
        }
    }

    /// Insert a call to a register with arguments.
    pub fn put_call_reg_with_arguments(&self, reg: ArmRegister, arguments: &[Argument]) {
        let gum_arguments = Self::convert_arguments(arguments);
        unsafe {
            gum_sys::gum_thumb_writer_put_call_reg_with_arguments_array(
                self.writer,
                reg as arm_reg,
                gum_arguments.len() as u32,
                gum_arguments.as_ptr(),
            )
        }
    }

    /// Insert a `b` (branch) to an immediate address.
    pub fn put_b_imm(&self, target: u64) {
        unsafe { gum_sys::gum_thumb_writer_put_b_imm(self.writer, target) }
    }

    /// Insert a `b` (branch) to a label.
    pub fn put_b_label(&self, label_id: u64) {
        unsafe { gum_sys::gum_thumb_writer_put_b_label(self.writer, label_id as *const c_void) }
    }

    /// Insert a wide `b` (branch) to a label.
    pub fn put_b_label_wide(&self, label_id: u64) {
        unsafe {
            gum_sys::gum_thumb_writer_put_b_label_wide(self.writer, label_id as *const c_void)
        }
    }

    /// Insert a `bx` (branch and exchange) to a register.
    pub fn put_bx_reg(&self, reg: ArmRegister) {
        unsafe { gum_sys::gum_thumb_writer_put_bx_reg(self.writer, reg as arm_reg) }
    }

    /// Insert a `bl` (branch with link) to an immediate address.
    pub fn put_bl_imm(&self, target: u64) {
        unsafe { gum_sys::gum_thumb_writer_put_bl_imm(self.writer, target) }
    }

    /// Insert a `bl` (branch with link) to a label.
    pub fn put_bl_label(&self, label_id: u64) {
        unsafe { gum_sys::gum_thumb_writer_put_bl_label(self.writer, label_id as *const c_void) }
    }

    /// Insert a `blx` (branch with link and exchange) to an immediate address.
    pub fn put_blx_imm(&self, target: u64) {
        unsafe { gum_sys::gum_thumb_writer_put_blx_imm(self.writer, target) }
    }

    /// Insert a `blx` (branch with link and exchange) to a register.
    pub fn put_blx_reg(&self, reg: ArmRegister) {
        unsafe { gum_sys::gum_thumb_writer_put_blx_reg(self.writer, reg as arm_reg) }
    }

    /// Insert a `cmp` (compare) register with immediate.
    pub fn put_cmp_reg_imm(&self, reg: ArmRegister, imm_value: u8) {
        unsafe { gum_sys::gum_thumb_writer_put_cmp_reg_imm(self.writer, reg as arm_reg, imm_value) }
    }

    /// Insert a `beq` (branch if equal) to a label.
    pub fn put_beq_label(&self, label_id: u64) {
        unsafe { gum_sys::gum_thumb_writer_put_beq_label(self.writer, label_id as *const c_void) }
    }

    /// Insert a `bne` (branch if not equal) to a label.
    pub fn put_bne_label(&self, label_id: u64) {
        unsafe { gum_sys::gum_thumb_writer_put_bne_label(self.writer, label_id as *const c_void) }
    }

    /// Insert a conditional branch to a label.
    pub fn put_b_cond_label(&self, cc: ArmConditionCode, label_id: u64) {
        unsafe {
            gum_sys::gum_thumb_writer_put_b_cond_label(
                self.writer,
                cc as u32,
                label_id as *const c_void,
            )
        }
    }

    /// Insert a wide conditional branch to a label.
    pub fn put_b_cond_label_wide(&self, cc: ArmConditionCode, label_id: u64) {
        unsafe {
            gum_sys::gum_thumb_writer_put_b_cond_label_wide(
                self.writer,
                cc as u32,
                label_id as *const c_void,
            )
        }
    }

    /// Insert a `cbz` (compare and branch if zero) instruction.
    pub fn put_cbz_reg_label(&self, reg: ArmRegister, label_id: u64) {
        unsafe {
            gum_sys::gum_thumb_writer_put_cbz_reg_label(
                self.writer,
                reg as arm_reg,
                label_id as *const c_void,
            )
        }
    }

    /// Insert a `cbnz` (compare and branch if non-zero) instruction.
    pub fn put_cbnz_reg_label(&self, reg: ArmRegister, label_id: u64) {
        unsafe {
            gum_sys::gum_thumb_writer_put_cbnz_reg_label(
                self.writer,
                reg as arm_reg,
                label_id as *const c_void,
            )
        }
    }

    /// Insert a `push` instruction for multiple registers.
    pub fn put_push_regs(&self, regs: &[ArmRegister]) -> bool {
        let reg_array: Vec<arm_reg> = regs.iter().map(|&r| r as arm_reg).collect();
        unsafe {
            gum_sys::gum_thumb_writer_put_push_regs_array(
                self.writer,
                reg_array.len() as u32,
                reg_array.as_ptr(),
            ) != 0
        }
    }

    /// Insert a `pop` instruction for multiple registers.
    pub fn put_pop_regs(&self, regs: &[ArmRegister]) -> bool {
        let reg_array: Vec<arm_reg> = regs.iter().map(|&r| r as arm_reg).collect();
        unsafe {
            gum_sys::gum_thumb_writer_put_pop_regs_array(
                self.writer,
                reg_array.len() as u32,
                reg_array.as_ptr(),
            ) != 0
        }
    }

    /// Insert a `vpush` instruction for a range of VFP registers.
    pub fn put_vpush_range(&self, first_reg: ArmRegister, last_reg: ArmRegister) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_vpush_range(
                self.writer,
                first_reg as arm_reg,
                last_reg as arm_reg,
            ) != 0
        }
    }

    /// Insert a `vpop` instruction for a range of VFP registers.
    pub fn put_vpop_range(&self, first_reg: ArmRegister, last_reg: ArmRegister) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_vpop_range(
                self.writer,
                first_reg as arm_reg,
                last_reg as arm_reg,
            ) != 0
        }
    }

    /// Insert a `ldr` (load register) from an address.
    pub fn put_ldr_reg_address(&self, reg: ArmRegister, address: u64) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_ldr_reg_address(self.writer, reg as arm_reg, address) != 0
        }
    }

    /// Insert a `ldr` (load register) with an immediate 32-bit value.
    pub fn put_ldr_reg_u32(&self, reg: ArmRegister, val: u32) -> bool {
        unsafe { gum_sys::gum_thumb_writer_put_ldr_reg_u32(self.writer, reg as arm_reg, val) != 0 }
    }

    /// Insert a `ldr` (load register) from a register.
    pub fn put_ldr_reg_reg(&self, dst_reg: ArmRegister, src_reg: ArmRegister) {
        unsafe {
            gum_sys::gum_thumb_writer_put_ldr_reg_reg(
                self.writer,
                dst_reg as arm_reg,
                src_reg as arm_reg,
            )
        }
    }

    /// Insert a `ldr` (load register) from a register with offset.
    pub fn put_ldr_reg_reg_offset(
        &self,
        dst_reg: ArmRegister,
        src_reg: ArmRegister,
        src_offset: usize,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_ldr_reg_reg_offset(
                self.writer,
                dst_reg as arm_reg,
                src_reg as arm_reg,
                src_offset as gsize,
            ) != 0
        }
    }

    /// Insert a `ldrb` (load byte) from a register.
    pub fn put_ldrb_reg_reg(&self, dst_reg: ArmRegister, src_reg: ArmRegister) {
        unsafe {
            gum_sys::gum_thumb_writer_put_ldrb_reg_reg(
                self.writer,
                dst_reg as arm_reg,
                src_reg as arm_reg,
            )
        }
    }

    /// Insert a `ldrh` (load halfword) from a register.
    pub fn put_ldrh_reg_reg(&self, dst_reg: ArmRegister, src_reg: ArmRegister) {
        unsafe {
            gum_sys::gum_thumb_writer_put_ldrh_reg_reg(
                self.writer,
                dst_reg as arm_reg,
                src_reg as arm_reg,
            )
        }
    }

    /// Insert a `vldr` (VFP load) from a register with offset.
    pub fn put_vldr_reg_reg_offset(
        &self,
        dst_reg: ArmRegister,
        src_reg: ArmRegister,
        src_offset: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_vldr_reg_reg_offset(
                self.writer,
                dst_reg as arm_reg,
                src_reg as arm_reg,
                src_offset as gssize,
            ) != 0
        }
    }

    /// Insert a `ldmia` (load multiple increment after) instruction.
    pub fn put_ldmia_reg_mask(&self, reg: ArmRegister, mask: u16) {
        unsafe { gum_sys::gum_thumb_writer_put_ldmia_reg_mask(self.writer, reg as arm_reg, mask) }
    }

    /// Insert a `str` (store register) to a register.
    pub fn put_str_reg_reg(&self, src_reg: ArmRegister, dst_reg: ArmRegister) {
        unsafe {
            gum_sys::gum_thumb_writer_put_str_reg_reg(
                self.writer,
                src_reg as arm_reg,
                dst_reg as arm_reg,
            )
        }
    }

    /// Insert a `str` (store register) to a register with offset.
    pub fn put_str_reg_reg_offset(
        &self,
        src_reg: ArmRegister,
        dst_reg: ArmRegister,
        dst_offset: usize,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_str_reg_reg_offset(
                self.writer,
                src_reg as arm_reg,
                dst_reg as arm_reg,
                dst_offset as gsize,
            ) != 0
        }
    }

    /// Insert a `mov` (move) register to register.
    pub fn put_mov_reg_reg(&self, dst_reg: ArmRegister, src_reg: ArmRegister) {
        unsafe {
            gum_sys::gum_thumb_writer_put_mov_reg_reg(
                self.writer,
                dst_reg as arm_reg,
                src_reg as arm_reg,
            )
        }
    }

    /// Insert a `mov` (move) immediate 8-bit value to register.
    pub fn put_mov_reg_u8(&self, dst_reg: ArmRegister, imm_value: u8) {
        unsafe {
            gum_sys::gum_thumb_writer_put_mov_reg_u8(self.writer, dst_reg as arm_reg, imm_value)
        }
    }

    /// Insert a `mrs` (move from special register) from CPSR to register.
    pub fn put_mov_reg_cpsr(&self, reg: ArmRegister) {
        unsafe { gum_sys::gum_thumb_writer_put_mov_reg_cpsr(self.writer, reg as arm_reg) }
    }

    /// Insert a `msr` (move to special register) from register to CPSR.
    pub fn put_mov_cpsr_reg(&self, reg: ArmRegister) {
        unsafe { gum_sys::gum_thumb_writer_put_mov_cpsr_reg(self.writer, reg as arm_reg) }
    }

    /// Insert an `add` (add) immediate to register.
    pub fn put_add_reg_imm(&self, dst_reg: ArmRegister, imm_value: isize) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_add_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                imm_value as gssize,
            ) != 0
        }
    }

    /// Insert an `add` (add) register to register.
    pub fn put_add_reg_reg(&self, dst_reg: ArmRegister, src_reg: ArmRegister) {
        unsafe {
            gum_sys::gum_thumb_writer_put_add_reg_reg(
                self.writer,
                dst_reg as arm_reg,
                src_reg as arm_reg,
            )
        }
    }

    /// Insert an `add` (add) register to register to register.
    pub fn put_add_reg_reg_reg(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_reg: ArmRegister,
    ) {
        unsafe {
            gum_sys::gum_thumb_writer_put_add_reg_reg_reg(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_reg as arm_reg,
            )
        }
    }

    /// Insert an `add` (add) register plus immediate to register.
    pub fn put_add_reg_reg_imm(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_value: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_add_reg_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_value as gssize,
            ) != 0
        }
    }

    /// Insert a `sub` (subtract) immediate from register.
    pub fn put_sub_reg_imm(&self, dst_reg: ArmRegister, imm_value: isize) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_sub_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                imm_value as gssize,
            ) != 0
        }
    }

    /// Insert a `sub` (subtract) register from register.
    pub fn put_sub_reg_reg(&self, dst_reg: ArmRegister, src_reg: ArmRegister) {
        unsafe {
            gum_sys::gum_thumb_writer_put_sub_reg_reg(
                self.writer,
                dst_reg as arm_reg,
                src_reg as arm_reg,
            )
        }
    }

    /// Insert a `sub` (subtract) register from register to register.
    pub fn put_sub_reg_reg_reg(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_reg: ArmRegister,
    ) {
        unsafe {
            gum_sys::gum_thumb_writer_put_sub_reg_reg_reg(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_reg as arm_reg,
            )
        }
    }

    /// Insert a `sub` (subtract) register minus immediate to register.
    pub fn put_sub_reg_reg_imm(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_value: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_sub_reg_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_value as gssize,
            ) != 0
        }
    }

    /// Insert an `and` (bitwise AND) instruction.
    pub fn put_and_reg_reg_imm(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_value: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_and_reg_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_value as gssize,
            ) != 0
        }
    }

    /// Insert an `orr` (bitwise OR) instruction.
    pub fn put_or_reg_reg_imm(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_value: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_or_reg_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_value as gssize,
            ) != 0
        }
    }

    /// Insert a `lsl` (logical shift left) instruction.
    pub fn put_lsl_reg_reg_imm(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_value: u8,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_lsl_reg_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_value,
            ) != 0
        }
    }

    /// Insert a `lsls` (logical shift left, setting flags) instruction.
    pub fn put_lsls_reg_reg_imm(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_value: u8,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_lsls_reg_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_value,
            ) != 0
        }
    }

    /// Insert a `lsrs` (logical shift right, setting flags) instruction.
    pub fn put_lsrs_reg_reg_imm(
        &self,
        dst_reg: ArmRegister,
        left_reg: ArmRegister,
        right_value: u8,
    ) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_lsrs_reg_reg_imm(
                self.writer,
                dst_reg as arm_reg,
                left_reg as arm_reg,
                right_value,
            ) != 0
        }
    }

    /// Insert a `mrs` (move from system register) instruction.
    pub fn put_mrs_reg_reg(&self, dst_reg: ArmRegister, src_reg: u32) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_mrs_reg_reg(self.writer, dst_reg as arm_reg, src_reg) != 0
        }
    }

    /// Insert a `msr` (move to system register) instruction.
    pub fn put_msr_reg_reg(&self, dst_reg: u32, src_reg: ArmRegister) -> bool {
        unsafe {
            gum_sys::gum_thumb_writer_put_msr_reg_reg(self.writer, dst_reg, src_reg as arm_reg) != 0
        }
    }

    /// Insert a `bkpt` (breakpoint) instruction with immediate.
    pub fn put_bkpt_imm(&self, imm: u8) {
        unsafe { gum_sys::gum_thumb_writer_put_bkpt_imm(self.writer, imm) }
    }

    /// Insert a breakpoint instruction.
    pub fn put_breakpoint(&self) {
        unsafe { gum_sys::gum_thumb_writer_put_breakpoint(self.writer) }
    }

    /// Insert a raw 16-bit instruction.
    pub fn put_instruction(&self, insn: u16) {
        unsafe { gum_sys::gum_thumb_writer_put_instruction(self.writer, insn) }
    }

    /// Insert a raw 32-bit wide instruction.
    pub fn put_instruction_wide(&self, upper: u16, lower: u16) {
        unsafe { gum_sys::gum_thumb_writer_put_instruction_wide(self.writer, upper, lower) }
    }

    /// Helper to convert Argument slice to GumArgument Vec.
    fn convert_arguments(arguments: &[Argument]) -> Vec<GumArgument> {
        arguments
            .iter()
            .map(|arg| match arg {
                Argument::Register(reg) => GumArgument {
                    type_: gum_sys::_GumArgType_GUM_ARG_REGISTER.try_into().unwrap(),
                    value: gum_sys::_GumArgument__bindgen_ty_1 { reg: *reg as i32 },
                },
                Argument::Address(addr) => GumArgument {
                    type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS.try_into().unwrap(),
                    value: gum_sys::_GumArgument__bindgen_ty_1 { address: *addr },
                },
            })
            .collect()
    }
}

#[cfg(target_arch = "arm")]
impl Drop for ThumbWriter {
    fn drop(&mut self) {
        if self.is_from_new {
            unsafe { gum_sys::gum_thumb_writer_unref(self.writer) }
        }
    }
}

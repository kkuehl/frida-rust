/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use {
    crate::{instruction_writer::InstructionWriter, NativePointer},
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
    gum_sys::{mips_reg, GumArgument},
};

#[cfg(not(any(
    feature = "module-names",
    feature = "backtrace",
    feature = "memory-access-monitor"
)))]
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The MIPS instruction writer.
#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
pub struct MipsInstructionWriter {
    pub(crate) writer: *mut gum_sys::_GumMipsWriter,
    is_from_new: bool,
}

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
impl InstructionWriter for MipsInstructionWriter {
    fn new(code_address: u64) -> Self {
        Self {
            writer: unsafe { gum_sys::gum_mips_writer_new(code_address as *mut c_void) },
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
        unsafe { gum_sys::gum_mips_writer_can_branch_directly_between(source, target) != 0 }
    }

    fn put_bytes(&self, bytes: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_mips_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32)
                != 0
        }
    }

    fn put_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_mips_writer_put_label(self.writer, id as *const c_void) != 0 }
    }

    fn reset(&self, code_address: u64) {
        unsafe { gum_sys::gum_mips_writer_reset(self.writer, code_address as *mut c_void) }
    }

    fn put_branch_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_mips_writer_put_j_address(self.writer, address) != 0 }
    }

    fn put_nop(&self) {
        unsafe { gum_sys::gum_mips_writer_put_nop(self.writer) }
    }

    fn flush(&self) -> bool {
        unsafe { gum_sys::gum_mips_writer_flush(self.writer) != 0 }
    }
}

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
impl MipsInstructionWriter {
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumMipsWriter) -> Self {
        Self {
            writer,
            is_from_new: false,
        }
    }

    /// Get the underlying frida gum writer object
    pub fn raw_writer(&self) -> *mut gum_sys::_GumMipsWriter {
        self.writer
    }

    /// Clear (free) the writer's internal state without deallocating the
    /// writer struct itself.
    pub fn clear(&self) {
        unsafe { gum_sys::gum_mips_writer_clear(self.writer) };
    }

    /// Get a pointer to the writer's current write cursor.
    pub fn cur(&self) -> NativePointer {
        NativePointer(unsafe { gum_sys::gum_mips_writer_cur(self.writer) })
    }

    /// Get the writer's byte offset from the original code address.
    pub fn offset(&self) -> u32 {
        unsafe { gum_sys::gum_mips_writer_offset(self.writer) }
    }

    /// Skip `n_bytes` bytes in the instruction stream.
    pub fn skip(&self, n_bytes: u32) {
        unsafe { gum_sys::gum_mips_writer_skip(self.writer, n_bytes) };
    }

    /// Write a call to the given address with arguments (array form).
    pub fn put_call_address_with_arguments_array(&self, func: u64, args: &[GumArgument]) {
        unsafe {
            gum_sys::gum_mips_writer_put_call_address_with_arguments_array(
                self.writer,
                func,
                args.len() as u32,
                args.as_ptr(),
            )
        }
    }

    /// Write a call to the given register with arguments (array form).
    pub fn put_call_reg_with_arguments_array(&self, reg: mips_reg, args: &[GumArgument]) {
        unsafe {
            gum_sys::gum_mips_writer_put_call_reg_with_arguments_array(
                self.writer,
                reg,
                args.len() as u32,
                args.as_ptr(),
            )
        }
    }

    /// Write a jump to the given address.
    pub fn put_j_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_mips_writer_put_j_address(self.writer, address) != 0 }
    }

    /// Write a jump to the given address without a NOP in the delay slot.
    pub fn put_j_address_without_nop(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_mips_writer_put_j_address_without_nop(self.writer, address) != 0 }
    }

    /// Write a jump to the given label.
    pub fn put_j_label(&self, label_id: u64) {
        unsafe { gum_sys::gum_mips_writer_put_j_label(self.writer, label_id as *const c_void) }
    }

    /// Write a jump register instruction.
    pub fn put_jr_reg(&self, reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_jr_reg(self.writer, reg) }
    }

    /// Write a jump and link to the given address.
    pub fn put_jal_address(&self, address: u32) {
        unsafe { gum_sys::gum_mips_writer_put_jal_address(self.writer, address) }
    }

    /// Write a jump and link register instruction.
    pub fn put_jalr_reg(&self, reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_jalr_reg(self.writer, reg) }
    }

    /// Write a branch with the given offset.
    pub fn put_b_offset(&self, offset: i32) {
        unsafe { gum_sys::gum_mips_writer_put_b_offset(self.writer, offset) }
    }

    /// Write a branch if equal instruction.
    pub fn put_beq_reg_reg_label(&self, right_reg: mips_reg, left_reg: mips_reg, label_id: u64) {
        unsafe {
            gum_sys::gum_mips_writer_put_beq_reg_reg_label(
                self.writer,
                right_reg,
                left_reg,
                label_id as *const c_void,
            )
        }
    }

    /// Write a return instruction.
    pub fn put_ret(&self) {
        unsafe { gum_sys::gum_mips_writer_put_ret(self.writer) }
    }

    /// Write a load address pseudo-instruction.
    pub fn put_la_reg_address(&self, reg: mips_reg, address: u64) {
        unsafe { gum_sys::gum_mips_writer_put_la_reg_address(self.writer, reg, address) }
    }

    /// Write a load upper immediate instruction.
    pub fn put_lui_reg_imm(&self, reg: mips_reg, imm: u32) {
        unsafe { gum_sys::gum_mips_writer_put_lui_reg_imm(self.writer, reg, imm) }
    }

    /// Write a doubleword shift left logical instruction (MIPS64).
    pub fn put_dsll_reg_reg(&self, dst_reg: mips_reg, src_reg: mips_reg, amount: u32) {
        unsafe { gum_sys::gum_mips_writer_put_dsll_reg_reg(self.writer, dst_reg, src_reg, amount) }
    }

    /// Write an OR immediate instruction.
    pub fn put_ori_reg_reg_imm(&self, rt: mips_reg, rs: mips_reg, imm: u32) {
        unsafe { gum_sys::gum_mips_writer_put_ori_reg_reg_imm(self.writer, rt, rs, imm) }
    }

    /// Write a load doubleword instruction (MIPS64).
    pub fn put_ld_reg_reg_offset(&self, dst_reg: mips_reg, src_reg: mips_reg, src_offset: usize) {
        unsafe {
            gum_sys::gum_mips_writer_put_ld_reg_reg_offset(self.writer, dst_reg, src_reg, src_offset)
        }
    }

    /// Write a load word instruction.
    pub fn put_lw_reg_reg_offset(&self, dst_reg: mips_reg, src_reg: mips_reg, src_offset: usize) {
        unsafe {
            gum_sys::gum_mips_writer_put_lw_reg_reg_offset(self.writer, dst_reg, src_reg, src_offset)
        }
    }

    /// Write a store word instruction.
    pub fn put_sw_reg_reg_offset(&self, src_reg: mips_reg, dst_reg: mips_reg, dst_offset: usize) {
        unsafe {
            gum_sys::gum_mips_writer_put_sw_reg_reg_offset(self.writer, src_reg, dst_reg, dst_offset)
        }
    }

    /// Write a move pseudo-instruction.
    pub fn put_move_reg_reg(&self, dst_reg: mips_reg, src_reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_move_reg_reg(self.writer, dst_reg, src_reg) }
    }

    /// Write an add unsigned instruction.
    pub fn put_addu_reg_reg_reg(
        &self,
        dst_reg: mips_reg,
        left_reg: mips_reg,
        right_reg: mips_reg,
    ) {
        unsafe {
            gum_sys::gum_mips_writer_put_addu_reg_reg_reg(
                self.writer,
                dst_reg,
                left_reg,
                right_reg,
            )
        }
    }

    /// Write an add immediate instruction.
    pub fn put_addi_reg_reg_imm(&self, dst_reg: mips_reg, left_reg: mips_reg, imm: i32) {
        unsafe { gum_sys::gum_mips_writer_put_addi_reg_reg_imm(self.writer, dst_reg, left_reg, imm) }
    }

    /// Write an add immediate instruction (single register form).
    pub fn put_addi_reg_imm(&self, dst_reg: mips_reg, imm: i32) {
        unsafe { gum_sys::gum_mips_writer_put_addi_reg_imm(self.writer, dst_reg, imm) }
    }

    /// Write a subtract immediate instruction.
    pub fn put_sub_reg_reg_imm(&self, dst_reg: mips_reg, left_reg: mips_reg, imm: i32) {
        unsafe { gum_sys::gum_mips_writer_put_sub_reg_reg_imm(self.writer, dst_reg, left_reg, imm) }
    }

    /// Write a push register pseudo-instruction.
    pub fn put_push_reg(&self, reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_push_reg(self.writer, reg) }
    }

    /// Write a pop register pseudo-instruction.
    pub fn put_pop_reg(&self, reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_pop_reg(self.writer, reg) }
    }

    /// Write a move from HI instruction.
    pub fn put_mfhi_reg(&self, reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_mfhi_reg(self.writer, reg) }
    }

    /// Write a move from LO instruction.
    pub fn put_mflo_reg(&self, reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_mflo_reg(self.writer, reg) }
    }

    /// Write a move to HI instruction.
    pub fn put_mthi_reg(&self, reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_mthi_reg(self.writer, reg) }
    }

    /// Write a move to LO instruction.
    pub fn put_mtlo_reg(&self, reg: mips_reg) {
        unsafe { gum_sys::gum_mips_writer_put_mtlo_reg(self.writer, reg) }
    }

    /// Write a break instruction.
    pub fn put_break(&self) {
        unsafe { gum_sys::gum_mips_writer_put_break(self.writer) }
    }

    /// Write a prologue trampoline.
    pub fn put_prologue_trampoline(&self, reg: mips_reg, address: u64) {
        unsafe { gum_sys::gum_mips_writer_put_prologue_trampoline(self.writer, reg, address) }
    }

    /// Write a raw instruction word.
    pub fn put_instruction(&self, insn: u32) {
        unsafe { gum_sys::gum_mips_writer_put_instruction(self.writer, insn) }
    }
}

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
impl Drop for MipsInstructionWriter {
    fn drop(&mut self) {
        if self.is_from_new {
            unsafe { gum_sys::gum_mips_writer_unref(self.writer) }
        }
    }
}

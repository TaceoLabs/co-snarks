//! A stack-discipline virtual register allocator.
//!
//! Expression lowering allocates a register for every intermediate result, but frees
//! operand registers back to the allocator as soon as the instruction consuming them is
//! emitted (see [`crate::codegen::expr::lower_expr`]). Because registers are only ever
//! freed back to a previously observed mark (never individually), a simple bump pointer
//! plus a high-water mark is enough to implement this: `alloc` never has to search for a
//! free slot, and `free_to` is O(1).
//!
//! One [`RegAlloc`] is used for field registers and a separate one for integer
//! registers; both are reset at the start of every template/function body (register
//! numbering is local to a single body, matching [`TemplateCode::num_field_regs`]/
//! [`TemplateCode::num_int_regs`]).
//!
//! [`TemplateCode::num_field_regs`]: circom_mpc_vm2::program::TemplateCode::num_field_regs
//! [`TemplateCode::num_int_regs`]: circom_mpc_vm2::program::TemplateCode::num_int_regs

/// A bump-pointer register allocator with stack-discipline freeing.
///
/// Registers are numbered from `0`; `alloc` hands out the next free number and advances
/// the pointer, `free_to` rewinds it back to an earlier [`mark`](Self::mark). The
/// allocator tracks the highest pointer value ever reached in `high_water`, which
/// becomes the frame's register-file size once lowering of a body is complete.
#[derive(Debug, Default, Clone)]
pub(crate) struct RegAlloc {
    /// The next register number that `alloc` will hand out.
    next: u32,
    /// The highest value `next` has ever reached — the frame's required register count.
    high_water: u32,
}

impl RegAlloc {
    /// Allocates a fresh register, returning its number.
    pub(crate) fn alloc(&mut self) -> u32 {
        self.alloc_n(1)
    }

    /// Allocates a contiguous block of `n` registers, returning the base register number.
    ///
    /// This is the counterpart to [`Self::alloc`] for instructions that write more than
    /// one consecutive register at runtime (e.g. `LoadN`/`StoreN`/`EqN`/`BinN`): the whole
    /// block must be reserved atomically so `high_water` accounts for every register the
    /// instruction actually touches, not just its base register.
    pub(crate) fn alloc_n(&mut self, n: u32) -> u32 {
        let r = self.next;
        self.next += n;
        self.high_water = self.high_water.max(self.next);
        r
    }

    /// Rewinds the allocator to a previously observed [`mark`](Self::mark), making every
    /// register allocated since that mark available for reuse.
    ///
    /// `mark` must be a value previously returned by [`Self::mark`] (or `0`) on this same
    /// allocator; passing anything else would let registers alias while still live.
    pub(crate) fn free_to(&mut self, mark: u32) {
        debug_assert!(mark <= self.next, "free_to must rewind, not advance");
        self.next = mark;
    }

    /// Returns a checkpoint that can later be passed to [`Self::free_to`].
    pub(crate) fn mark(&self) -> u32 {
        self.next
    }

    /// Returns the highest register count ever in use — the required frame size.
    pub(crate) fn high_water(&self) -> u32 {
        self.high_water
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_bumps_and_tracks_high_water() {
        let mut regs = RegAlloc::default();
        assert_eq!(regs.alloc(), 0);
        assert_eq!(regs.alloc(), 1);
        assert_eq!(regs.high_water(), 2);
    }

    #[test]
    fn alloc_n_reserves_a_contiguous_block_and_tracks_high_water() {
        let mut regs = RegAlloc::default();
        assert_eq!(regs.alloc(), 0);
        assert_eq!(regs.alloc_n(3), 1, "block must start right after reg 0");
        assert_eq!(
            regs.high_water(),
            4,
            "high water must account for the whole n-register block"
        );
        assert_eq!(
            regs.alloc(),
            4,
            "next alloc must start after the reserved block"
        );
    }

    #[test]
    fn free_to_reuses_registers_and_keeps_high_water() {
        let mut regs = RegAlloc::default();
        let mark = regs.mark();
        regs.alloc();
        regs.alloc();
        regs.free_to(mark);
        assert_eq!(
            regs.alloc(),
            0,
            "freed registers must be reused from the mark"
        );
        assert_eq!(regs.high_water(), 2, "high water mark must not be rewound");
    }
}

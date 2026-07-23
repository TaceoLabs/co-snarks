//! The variable-binding environment.
//!
//! Circom `var`s can be scalars, arrays with statically-known indices, or (once a loop
//! variable is promoted — see [`crate::codegen::stmt::lower_loop`]) an integer-register
//! mirror consulted only for *index-position* reads (see
//! [`crate::codegen::index::eval_index`]). [`Env`] tracks, per variable slot, which of
//! these addressing modes currently applies.
use std::collections::HashMap;

/// How a circom `var` slot is currently addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binding {
    /// Default: the variable lives in its var slot; every access (value or index
    /// position) reads/writes that slot directly. Implicit for any slot with no entry in
    /// [`Env`] — nothing needs to construct this variant explicitly, but it's kept
    /// (rather than represented purely by absence) since the brief's interface names it
    /// and callers reading match arms benefit from the explicit default being spelled
    /// out.
    #[allow(dead_code)] // never explicitly constructed -- see above
    FieldSlot,
    /// Promoted induction variable ([`crate::codegen::stmt::lower_loop`]'s conforming
    /// path): an integer register mirrors the variable's field slot for the loop's whole
    /// extent. The field slot stays authoritative — value-position reads still load it —
    /// only index-position reads resolve to [`Addr::Affine`](circom_mpc_vm2::isa::Addr::Affine)
    /// via this register (see [`crate::codegen::index::eval_index`]'s `ireg_binding`).
    IReg {
        /// The integer register mirroring the variable's field slot.
        ireg: u8,
    },
    /// Unrolled iteration (Task 5): the variable's value is a compile-time constant.
    #[allow(dead_code)] // constructed starting Task 5
    ConstUsize(usize),
}

/// The variable-binding environment: tracks how each variable slot is currently
/// addressed (see [`Binding`]). Reset per template/function body ([`CodeGen::reset_body`](
/// crate::codegen::CodeGen)); bindings are pushed/popped around the scope they apply to
/// (a loop's extent) via [`Self::bind`]/[`Self::restore`], so nested loops over distinct
/// variable slots never interfere with each other, and a slot's binding is always
/// restored exactly once its owning scope ends.
#[derive(Debug, Default, Clone)]
pub(crate) struct Env {
    bindings: HashMap<usize, Binding>,
}

impl Env {
    /// Binds `slot` to `binding` for the duration of some scope, returning whatever was
    /// previously bound (if anything) so the caller can hand it straight to
    /// [`Self::restore`] once that scope ends.
    pub(crate) fn bind(&mut self, slot: usize, binding: Binding) -> Option<Binding> {
        self.bindings.insert(slot, binding)
    }

    /// Ends a binding's scope: reinstates `previous` (as returned by the matching
    /// [`Self::bind`] call) if it was `Some`, otherwise removes `slot` entirely, falling
    /// back to the implicit default ([`Binding::FieldSlot`]).
    pub(crate) fn restore(&mut self, slot: usize, previous: Option<Binding>) {
        match previous {
            Some(binding) => {
                self.bindings.insert(slot, binding);
            }
            None => {
                self.bindings.remove(&slot);
            }
        }
    }

    /// The current binding for `slot`, or `None` for the implicit default
    /// ([`Binding::FieldSlot`]).
    pub(crate) fn get(&self, slot: usize) -> Option<Binding> {
        self.bindings.get(&slot).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbound_slot_reads_as_none() {
        let env = Env::default();
        assert_eq!(env.get(0), None);
    }

    #[test]
    fn bind_then_get_returns_the_binding() {
        let mut env = Env::default();
        env.bind(3, Binding::IReg { ireg: 2 });
        assert_eq!(env.get(3), Some(Binding::IReg { ireg: 2 }));
    }

    #[test]
    fn restore_with_none_removes_the_binding() {
        let mut env = Env::default();
        let previous = env.bind(3, Binding::IReg { ireg: 2 });
        assert_eq!(previous, None);
        env.restore(3, previous);
        assert_eq!(env.get(3), None);
    }

    #[test]
    fn restore_with_some_reinstates_the_previous_binding() {
        let mut env = Env::default();
        env.bind(3, Binding::ConstUsize(7));
        let previous = env.bind(3, Binding::IReg { ireg: 2 });
        assert_eq!(previous, Some(Binding::ConstUsize(7)));
        env.restore(3, previous);
        assert_eq!(env.get(3), Some(Binding::ConstUsize(7)));
    }

    #[test]
    fn distinct_slots_do_not_interfere() {
        let mut env = Env::default();
        env.bind(1, Binding::IReg { ireg: 0 });
        env.bind(2, Binding::IReg { ireg: 1 });
        assert_eq!(env.get(1), Some(Binding::IReg { ireg: 0 }));
        assert_eq!(env.get(2), Some(Binding::IReg { ireg: 1 }));
    }
}

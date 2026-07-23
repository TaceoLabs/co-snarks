//! The variable-binding environment.
//!
//! Circom `var`s can be scalars, arrays with statically-known indices, or (once loops are
//! unrolled/lowered) arrays addressed with a loop-variable-dependent index. Task 4 will
//! turn this into a real binding table (`IReg`/`FieldSlot`/`ConstUsize` per variable),
//! resolving each access against the current addressing mode.
//!
//! For now every variable access in the IR arrives as a constant `dag_local`-style
//! index already (mirroring signal addressing — see [`crate::codegen::expr`]), so no
//! binding state is needed yet; this type is a placeholder kept in [`CodeGen`](
//! crate::codegen::CodeGen) so later tasks don't need to change its shape.
#[derive(Debug, Default, Clone)]
pub(crate) struct Env;

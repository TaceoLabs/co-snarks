#![warn(missing_docs)]
//! Register-based MPC-VM for the circom witness extension.
//!
//! This crate is the successor of [`circom-mpc-vm`](https://docs.rs/circom-mpc-vm), which
//! interprets the same circom-derived control flow as a stack-based bytecode VM: a
//! linear opcode list executed by pushing/popping field- and index-valued stacks.
//! `circom-mpc-vm2` instead compiles that control flow ahead of time down to a flat,
//! three-address instruction stream ([`isa::Instr`]) operating on integer-indexed
//! registers and signal RAM — the same shift from "stack machine" to "register machine"
//! that motivates most bytecode-VM rewrites, aimed at removing the stack push/pop
//! traffic and opcode dispatch overhead from the hot path.
//!
//! The compilation side of that split — circom AST/R1CS in, [`program::CompiledProgram`]
//! out — lives in the (forthcoming) `circom-mpc-compiler2` crate, mirroring how
//! `circom-mpc-compiler` feeds `circom-mpc-vm` today. This crate owns only the
//! *execution* half: given a [`program::CompiledProgram`], drive it to a finished
//! witness. Programs can also be hand-assembled directly (bypassing the compiler
//! entirely), which is how this crate's own tests — and the [example](#example) below —
//! exercise the VM.
//!
//! # Architecture
//!
//! - **ISA** ([`isa`]): [`isa::Instr`] is a three-address instruction set — every
//!   operand is an addressing mode ([`isa::Src`]/[`isa::Dst`]/[`isa::Addr`]), not a
//!   stack slot, so an instruction such as [`isa::Instr::Bin`] reads two operands and
//!   writes one register in a single step. Addressing modes range from a fixed
//!   constant-table or signal index ([`isa::Addr::Const`]) through loop-affine
//!   addressing ([`isa::Addr::Affine`], for stepping through arrays) to a fully
//!   dynamic index held in an integer register ([`isa::Addr::Dynamic`]).
//! - **Register frames** ([`exec::Frame`]): each template or function activation gets
//!   its own frame of field registers (`regs`, expression temporaries), integer
//!   registers (`iregs`, loop/addressing indices), and var slots (`vars`, circom
//!   `var`s) — allocated once per activation from sizes recorded in
//!   [`program::TemplateCode`]/[`program::FunctionCode`], rather than growing a
//!   name-keyed environment as a tree-walker would. [`exec::Machine`] owns the signal
//!   RAM shared by the whole component tree and drives the fetch/dispatch loop
//!   ([`exec::Machine::run_main`]) over template bodies, function calls, and
//!   subcomponents.
//! - **Drivers** ([`driver`], [`drivers`]): every arithmetic/comparison op in
//!   [`isa::Instr`] maps 1:1 to a method on [`driver::VmDriver`], so the interpreter
//!   loop never branches on "are we running MPC or not" — that choice is fully
//!   contained in which [`driver::VmDriver`] impl is plugged in.
//!   [`drivers::plain::PlainDriver`] executes directly on field elements for local/test
//!   runs; a real deployment plugs in a driver backed by an MPC protocol (Rep3,
//!   Shamir, ...) whose `VmType` is a secret share instead of `F`.
//! - **Predication**: circom `if` branches on a secret condition must still execute
//!   *both* arms (revealing which arm ran would leak information about the secret),
//!   selecting the right result with an oblivious multiplexer at the end. This is
//!   compiled to [`isa::Instr::SharedIf`]/[`isa::Instr::SharedElse`]/[`isa::Instr::SharedEnd`]:
//!   a public condition still short-circuits to one branch, but a shared condition
//!   pushes a predication level, runs both arms, and merges writes to `var`/`signal`
//!   destinations via [`driver::VmDriver::cmux`] — register (`Reg`) writes are never
//!   predicated, since registers are branch-local temporaries that don't outlive the
//!   branch.
//!
//! Programs are produced by `circom-mpc-compiler2` (or hand-assembled, as below) and
//! executed by a [`api::WitnessExtension`] instantiated with a driver implementing
//! [`driver::VmDriver`]; [`api::PlainWitnessExtension`] is the convenience alias for
//! [`drivers::plain::PlainDriver`].
//!
//! # Example
//!
//! Hand-assembling and running the two-signal circuit `out <== a * b` (no compiler
//! involved): one [`isa::Instr::Bin`] multiplies the two input signals into a
//! register, one [`isa::Instr::Mov`] writes the result to the output signal, and
//! [`isa::Instr::Return`] ends the template body. Signal RAM is laid out globally as
//! `[0] = 1` (the constant-one signal every program has at index 0), `[1] = out`,
//! `[2] = a`, `[3] = b` — but in-template [`isa::Addr::Const`] addresses are relative
//! to the *component's own* signals, so within the main component's instructions
//! `out`/`a`/`b` are addressed as local indices `0`/`1`/`2` (global index = local
//! index + 1, since global index 0 is reserved for the constant).
//!
//! ```rust
//! use ark_bn254::Fr;
//! use circom_mpc_vm2::api::PlainWitnessExtension;
//! use circom_mpc_vm2::isa::{Addr, BinOp, Dst, Instr, Src, TemplId};
//! use circom_mpc_vm2::program::{CompiledProgram, DebugInfo, InputInfo, TemplateCode, VMConfig};
//! use std::collections::HashMap;
//! use std::sync::Arc;
//!
//! let template = TemplateCode {
//!     instrs: vec![
//!         Instr::Bin {
//!             op: BinOp::Mul,
//!             dst: 0,
//!             a: Src::Signal(Addr::Const(1)), // a
//!             b: Src::Signal(Addr::Const(2)), // b
//!         },
//!         Instr::Mov {
//!             dst: Dst::Signal(Addr::Const(0)), // out
//!             src: Src::Reg(0),
//!         },
//!         Instr::Return,
//!     ],
//!     num_field_regs: 1,
//!     num_int_regs: 0,
//!     num_vars: 0,
//!     input_signals: 2,
//!     output_signals: 1,
//!     sub_components: 0,
//!     mappings: vec![],
//!     name_id: 0,
//!     symbol_id: 0,
//! };
//! let mut output_mapping = HashMap::new();
//! output_mapping.insert("out".to_string(), (1, 1));
//! let program = Arc::new(CompiledProgram {
//!     templates: vec![template],
//!     functions: vec![],
//!     constants: vec![],
//!     strings: vec![],
//!     main: TemplId(0),
//!     total_signals: 4,
//!     main_inputs: 2,
//!     main_outputs: 1,
//!     main_input_list: vec![
//!         InputInfo { name: "a".to_string(), offset: 2, size: 1 },
//!         InputInfo { name: "b".to_string(), offset: 3, size: 1 },
//!     ],
//!     output_mapping,
//!     signal_to_witness: vec![0, 1, 2, 3],
//!     public_inputs: vec![],
//!     debug: DebugInfo { names: vec!["Multiplier".to_string()] },
//! });
//!
//! let wex = PlainWitnessExtension::new_plain(program, VMConfig::default());
//! let finalized = wex
//!     .run_with_flat(vec![Fr::from(6u64), Fr::from(7u64)], 0)
//!     .expect("run_with_flat");
//! assert_eq!(finalized.get_output("out"), Some(vec![Fr::from(42u64)]));
//! ```
pub mod api;
pub mod driver;
pub mod drivers;
#[doc(hidden)]
pub mod exec;
pub mod isa;
pub mod program;

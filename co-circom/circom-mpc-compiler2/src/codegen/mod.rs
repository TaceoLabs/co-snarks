//! Lowering from the circom-compiler [`CircomCircuit`] representation to a
//! `circom-mpc-vm2` [`CompiledProgram`].
//!
//! Compilation is two-phase:
//!  1. **Id assignment** ([`compile`]'s first loop): every monomorphized template and
//!     function gets a stable [`TemplId`]/[`FnId`], keyed by its unique `header`, and
//!     the constant/string tables are parsed. This happens before any body is lowered
//!     so that `CreateCmp`/`CallFn` (Task 7/8) can resolve their targets regardless of
//!     declaration order.
//!  2. **Body lowering** ([`CodeGen::lower_template`] et al.): each template/function
//!     body is walked instruction by instruction, translating circom's stack-based IR
//!     buckets (`ComputeBucket`, `LoadBucket`, `StoreBucket`, ...) into the register ISA
//!     ([`circom_mpc_vm2::isa::Instr`]). [`expr`] handles expression-position IR
//!     (constants, loads, computed values); [`stmt`] handles statement-position IR
//!     (stores and — once their tasks land — asserts, branches, loops, calls, ...).
//!
//! Every bucket kind not yet lowered by whichever task's turn it is is a
//! `bail!("not yet lowered: ...")` stub — see the crate's task plan for the breakdown.
//! As of this crate's function-lowering task, the only remaining stub is subcomponent
//! addressing (`CreateCmp`/`InputSub`/`OutputSub`/`SubcmpSignal`, Task 8) — every other
//! bucket kind, including function bodies and calls
//! ([`CodeGen::lower_function`]/[`stmt::lower_call`]), lowers fully.
use crate::CompilerConfig;
use crate::frontend::OutputMapping;
use ark_ff::PrimeField;
use circom_compiler::circuit_design::function::FunctionCodeInfo;
use circom_compiler::circuit_design::template::TemplateCodeInfo;
use circom_compiler::compiler_interface::Circuit as CircomCircuit;
use circom_compiler::intermediate_representation::ir_interface::Instruction;
use circom_mpc_vm2::isa::{FnId, Instr, TemplId};
use circom_mpc_vm2::program::{CompiledProgram, DebugInfo, FunctionCode, InputInfo, TemplateCode};
use eyre::{Result, eyre};
use std::collections::HashMap;

mod env;
mod expr;
mod index;
mod regalloc;
mod stmt;

use env::Env;
use regalloc::RegAlloc;

/// Lowers a parsed and constraint-generated [`CircomCircuit`] into a [`CompiledProgram`]
/// runnable by `circom-mpc-vm2`. See the module docs for the two-phase overview.
pub(crate) fn compile<F: PrimeField>(
    circuit: CircomCircuit,
    output_mapping: OutputMapping,
    public_inputs: Vec<String>,
    config: &CompilerConfig,
) -> Result<CompiledProgram<F>> {
    let mut cg = CodeGen::<F>::new(config);

    // Phase 1: id assignment + constant/string tables (see module docs).
    for (i, templ) in circuit.templates.iter().enumerate() {
        cg.templ_ids
            .insert(templ.header.clone(), TemplId(u32::try_from(i)?));
    }
    for (i, fun) in circuit.functions.iter().enumerate() {
        cg.fn_ids
            .insert(fun.header.clone(), FnId(u32::try_from(i)?));
    }
    tracing::debug!(
        "assigned {} template id(s), {} function id(s)",
        cg.templ_ids.len(),
        cg.fn_ids.len()
    );
    cg.constants = circuit
        .c_producer
        .get_field_constant_list()
        .iter()
        .map(|s| {
            s.parse::<F>()
                .map_err(|_| eyre!("cannot parse field constant {s:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    // Seed the reverse lookup `const_id` (unrolled-loop lowering, Task 5) uses to avoid
    // re-adding a value the circuit's own constant table already tables.
    for (i, c) in cg.constants.iter().enumerate() {
        cg.const_ids.insert(*c, u32::try_from(i)?);
    }
    let strings = circuit.c_producer.get_string_table().clone();

    // Phase 2: lower every function body first (templates may `Call` into any of them,
    // regardless of declaration order — id assignment above already made every `FnId`
    // resolvable), then every template body.
    let functions = circuit
        .functions
        .iter()
        .map(|fun| cg.lower_function(fun))
        .collect::<Result<Vec<_>>>()?;
    let templates = circuit
        .templates
        .iter()
        .map(|templ| {
            let mappings = circuit
                .c_producer
                .io_map
                .get(&templ.id)
                .map(|defs| defs.iter().map(|d| d.offset as u32).collect())
                .unwrap_or_default();
            cg.lower_template(templ, mappings)
        })
        .collect::<Result<Vec<_>>>()?;

    let main_header = &circuit.c_producer.main_header;
    let main = *cg
        .templ_ids
        .get(main_header)
        .ok_or_else(|| eyre!("main template {main_header:?} was never assigned an id"))?;

    let main_input_list = circuit
        .c_producer
        .main_input_list
        .iter()
        .map(|info| InputInfo {
            name: info.name.clone(),
            offset: info.start,
            size: info.size,
        })
        .collect();

    Ok(CompiledProgram {
        templates,
        functions,
        constants: cg.constants,
        strings,
        main,
        total_signals: circuit.c_producer.total_number_of_signals,
        main_inputs: circuit.c_producer.number_of_main_inputs,
        main_outputs: circuit.c_producer.number_of_main_outputs,
        main_input_list,
        output_mapping,
        signal_to_witness: circuit.c_producer.witness_to_signal_list.clone(),
        public_inputs,
        debug: DebugInfo {
            names: cg.names.into_names(),
        },
    })
}

/// A trivial string interner backing [`DebugInfo::names`]: hands out a stable `u32` id
/// for every distinct string it sees, in first-seen order.
#[derive(Debug, Default)]
pub(crate) struct NameInterner {
    names: Vec<String>,
    ids: HashMap<String, u32>,
}

impl NameInterner {
    /// Returns the id for `s`, interning (appending) it if this is the first time it's
    /// seen.
    pub(crate) fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.ids.get(s) {
            return id;
        }
        let id = u32::try_from(self.names.len()).expect("more than u32::MAX interned names");
        self.names.push(s.to_owned());
        self.ids.insert(s.to_owned(), id);
        id
    }

    /// Consumes the interner, returning the name table for [`DebugInfo`].
    pub(crate) fn into_names(self) -> Vec<String> {
        self.names
    }
}

/// Per-compilation codegen state.
///
/// `templ_ids`/`fn_ids`/`names`/`constants`/`config` are built once (phase 1) and held
/// for the whole compilation; `instrs`/`regs`/`iregs`/`env` are per-body and reset by
/// [`CodeGen::reset_body`] before lowering each template/function (phase 2).
pub(crate) struct CodeGen<'c, F> {
    /// Stable [`TemplId`] for every monomorphized template, keyed by its unique
    /// `header` (e.g. `"Multiplier2_0"`).
    pub(crate) templ_ids: HashMap<String, TemplId>,
    /// Stable [`FnId`] for every function, keyed by its unique `header`.
    pub(crate) fn_ids: HashMap<String, FnId>,
    /// Interned name table backing [`DebugInfo::names`].
    pub(crate) names: NameInterner,
    /// The circuit's field-constant table, parsed once up front.
    pub(crate) constants: Vec<F>,
    /// Reverse lookup for [`Self::const_id`]: the id already assigned to a field value
    /// that's been interned into [`Self::constants`], so a repeated value (e.g. the same
    /// unrolled-loop induction-variable constant appearing in two different loops) reuses
    /// its existing id instead of growing the table. Seeded from [`Self::constants`]
    /// once, in [`compile`], then only grows via [`Self::const_id`].
    pub(crate) const_ids: HashMap<F, u32>,
    /// The compiler configuration.
    pub(crate) config: &'c CompilerConfig,
    /// The instruction stream of the body currently being lowered.
    pub(crate) instrs: Vec<Instr>,
    /// Field-register allocator for the body currently being lowered.
    pub(crate) regs: RegAlloc,
    /// Integer-register allocator for the body currently being lowered.
    pub(crate) iregs: RegAlloc,
    /// Variable-binding environment for the body currently being lowered (see
    /// [`env::Binding`]).
    pub(crate) env: Env,
    /// The last constant value stored to each variable slot, tracked while lowering the
    /// body currently in progress — the compile-time-known "value before the loop" a
    /// conforming loop's induction variable needs (see `stmt::detect_conforming`'s docs
    /// for the exact tracking/invalidation rules).
    pub(crate) last_const_store: HashMap<usize, u32>,
    /// Memoizes [`stmt::estimate_unrolled_body`]'s result (one iteration's instruction
    /// count) per *lexical* loop, keyed by the [`LoopBucket`](circom_compiler::
    /// intermediate_representation::ir_interface::LoopBucket)'s own address (`lb as *const
    /// LoopBucket as usize`) rather than its `message_id`.
    ///
    /// `message_id` looks tempting (it reads like a per-AST-node id) but isn't one:
    /// tracing `circom`'s own translator (`circuit_design::build::build_template_instances`
    /// / `intermediate_representation::translate::State`) shows it's assigned once per
    /// *template instantiation* and copied verbatim onto every bucket produced while
    /// translating that template's body — confirmed empirically (a debug probe on
    /// `tests/circuits/loop_triple_nested.circom`'s three nested loops printed
    /// `message_id=0` for all three). Keying on it alone would collide every lexical loop
    /// within the same template into one cache slot, so whichever loop's estimate is
    /// computed (or overwritten) last would silently clobber the entry for every other
    /// loop in that template — the exact per-context-differing-size hazard this cache
    /// needs to rule out, just from a different cause than an enclosing loop's bindings.
    /// A `LoopBucket`'s address is unique per AST node and stable for as long as the
    /// template/function body owning it is being lowered (the IR tree is an owned,
    /// immutable structure for that entire pass; nothing relocates it), which is exactly
    /// this cache's lifetime — reset alongside everything else in [`Self::reset_body`], so
    /// distinct templates/functions never share entries even if their addresses were ever
    /// reused by the allocator afterwards.
    ///
    /// Why caching the estimate at all is exact, not just a fast-path heuristic: a nested
    /// loop's own conformance (`stmt::detect_conforming`) can only recognize a bound/step/
    /// init that are already compile-time constants embedded directly in the IR (a `Value`
    /// bucket, or a preceding `Store` of one — never a `Load` of anything, let alone an
    /// enclosing loop's induction variable), so every input to
    /// [`stmt::estimate_unrolled_body`] for a given lexical loop is fixed by the source
    /// text alone — re-deriving it under a different outer-loop iteration (a different
    /// [`env::Binding::ConstUsize`] for some *other* slot) always reproduces the identical
    /// count. Caching it here turns what would otherwise be a full re-lowering-and-discard
    /// pass, repeated once per *enclosing* iteration (see [`stmt::try_unroll_loop`]'s doc
    /// comment — this is what made nested unrolling's estimation cost blow up with nesting
    /// depth), into a single lowering pass per lexical loop, however many times its
    /// enclosing loop(s) iterate.
    ///
    /// Only ever consulted/populated while [`Self::unroll_estimate_nesting`] is `0` — see
    /// that field for why a cache entry written *while nested inside* an ancestor's own
    /// throwaway size-estimation pass can't be trusted for reuse in that ancestor's real,
    /// committed lowering.
    pub(crate) unroll_estimate_cache: HashMap<usize, usize>,
    /// How many [`stmt::estimate_unrolled_body`] calls are currently on the stack (`0`
    /// outside of any of them). Gates [`Self::unroll_estimate_cache`]: a loop's estimate is
    /// only read from or written to the cache while this is `0`, i.e. while the *current*
    /// invocation is part of real, committed lowering — never while it's part of some
    /// ancestor loop's own throwaway single-sample size assessment.
    ///
    /// Why this matters: [`stmt::estimate_unrolled_body`] temporarily binds its loop's own
    /// slot to [`env::Binding::ConstUsize`] for the duration of its single sample —
    /// *regardless* of what that loop's real, final decision turns out to be. If it later
    /// decides *not* to unroll, its real body lowering instead binds the slot to
    /// [`env::Binding::IReg`] (see [`stmt::lower_conforming_loop`]) — a different address
    /// folding for any nested loop whose body combines *two or more* enclosing induction
    /// variables in one address expression (e.g. `a[i][j][k]` in a 3-deep nest): `Const ∘
    /// Const` and `Affine ∘ Const` both fold with zero added instructions
    /// (`codegen::index`'s `try_fold_const`), but `Affine ∘ Affine` doesn't fold at all and
    /// must materialize both operands with real `IMul`/`IAdd` instructions. A cache entry
    /// for such a nested loop, first written while two-or-more ancestors were *all*
    /// momentarily `ConstUsize` (inside their own nested self-assessments), would
    /// under-count its real cost if reused later once those same ancestors have for-real
    /// settled on staying rolled (`IReg`) — this field's gating rules that out entirely: an
    /// ancestor's own self-assessment always runs at nesting `> 0` (never touches the
    /// cache), so the only entries ever cached are ones computed — and later only ever
    /// reused — under nesting `0`, where every enclosing loop's binding kind is whatever it
    /// has *finally, actually* committed to, consistently, every single time (an ancestor's
    /// unroll/roll decision is itself deterministic given the same lexical loop and
    /// [`CompilerConfig`], so it never differs between separate nesting-`0` invocations).
    pub(crate) unroll_estimate_nesting: usize,
}

impl<'c, F: PrimeField> CodeGen<'c, F> {
    /// Creates a fresh, empty codegen state.
    fn new(config: &'c CompilerConfig) -> Self {
        Self {
            templ_ids: HashMap::new(),
            fn_ids: HashMap::new(),
            names: NameInterner::default(),
            constants: Vec::new(),
            const_ids: HashMap::new(),
            config,
            instrs: Vec::new(),
            regs: RegAlloc::default(),
            iregs: RegAlloc::default(),
            env: Env::default(),
            last_const_store: HashMap::new(),
            unroll_estimate_cache: HashMap::new(),
            unroll_estimate_nesting: 0,
        }
    }

    /// Resets the per-body state before lowering a new template/function.
    fn reset_body(&mut self) {
        self.instrs.clear();
        self.regs = RegAlloc::default();
        self.iregs = RegAlloc::default();
        self.env = Env::default();
        self.last_const_store.clear();
        self.unroll_estimate_cache.clear();
        self.unroll_estimate_nesting = 0;
    }

    /// Allocates a fresh field register, checked against the ISA's `u16` register-index
    /// width.
    pub(crate) fn alloc_freg(&mut self) -> Result<u16> {
        u16::try_from(self.regs.alloc())
            .map_err(|_| eyre!("template/function body exceeds 65535 field registers"))
    }

    /// Allocates a contiguous block of `n` field registers (for instructions like
    /// [`Instr::LoadN`] that write `n` consecutive registers at runtime), returning the
    /// base register checked against the ISA's `u16` register-index width.
    pub(crate) fn alloc_freg_n(&mut self, n: u32) -> Result<u16> {
        u16::try_from(self.regs.alloc_n(n))
            .map_err(|_| eyre!("template/function body exceeds 65535 field registers"))
    }

    /// Interns `v` into [`Self::constants`], returning its existing id (via
    /// [`Self::const_ids`]) if this exact value has been seen before, or appending a new
    /// entry otherwise. Used by unrolled-loop lowering ([`stmt::lower_loop`]'s unrolling
    /// path) to turn a compile-time-known induction-variable value into a field constant
    /// on demand, without duplicating an already-tabled value.
    pub(crate) fn const_id(&mut self, v: F) -> Result<u32> {
        if let Some(&id) = self.const_ids.get(&v) {
            return Ok(id);
        }
        let id = u32::try_from(self.constants.len())
            .map_err(|_| eyre!("constant table exceeds u32::MAX entries"))?;
        self.constants.push(v);
        self.const_ids.insert(v, id);
        Ok(id)
    }

    /// Allocates a fresh integer register, checked against the ISA's `u8` register-index
    /// width. Realistically unreachable (it would take 256 levels of nested dynamic
    /// addressing in a single statement), but `RegAlloc` itself has no width limit, so
    /// this is where the ISA's actual budget is enforced.
    pub(crate) fn alloc_ireg(&mut self) -> Result<u8> {
        u8::try_from(self.iregs.alloc())
            .map_err(|_| eyre!("template/function body exceeds 255 integer registers"))
    }

    /// Backpatches a previously emitted jump/branch instruction's placeholder target now
    /// that it's known — the "add a `patch(idx, target)` helper" the loop-lowering brief
    /// asks for: a loop's head emits `Instr::JmpIfZero` with a placeholder target
    /// (`u32::MAX`) before the body's length (hence the loop's exit index) is known; once
    /// the whole loop has been lowered, this fixes it up. [`stmt::lower_branch`] (Task 6)
    /// reuses the same helper for `Instr::SharedIf`'s `else_target` and
    /// `Instr::SharedElse`'s `end_target` — same placeholder-then-backpatch discipline,
    /// just different field names on the target instruction. `idx` must index an
    /// already-emitted `Jmp`/`JmpIfZero`/`SharedIf`/`SharedElse` in [`Self::instrs`] —
    /// anything else is a codegen bug, not a user-triggerable error, so this panics rather
    /// than returning `Result`.
    pub(crate) fn patch(&mut self, idx: usize, target: u32) {
        match &mut self.instrs[idx] {
            Instr::Jmp { target: t }
            | Instr::JmpIfZero { target: t, .. }
            | Instr::SharedIf { else_target: t, .. }
            | Instr::SharedElse { end_target: t } => *t = target,
            other => unreachable!("CodeGen::patch called on non-jump instruction {other:?}"),
        }
    }

    /// Lowers one template body into a [`TemplateCode`], resetting per-body state
    /// first. `mappings` is this template's io-map offsets, computed by the caller from
    /// `circuit.c_producer.io_map` (used for mapped subcomponent signal access, Task 8).
    fn lower_template(
        &mut self,
        templ: &TemplateCodeInfo,
        mappings: Vec<u32>,
    ) -> Result<TemplateCode> {
        self.reset_body();
        for inst in templ.body.iter() {
            stmt::lower_stmt(self, inst)?;
        }
        self.instrs.push(Instr::Return);
        let num_field_regs = self
            .regs
            .high_water()
            .try_into()
            .map_err(|_| eyre!("template {} exceeds 65535 field registers", templ.name))?;
        let num_int_regs = self
            .iregs
            .high_water()
            .try_into()
            .map_err(|_| eyre!("template {} exceeds 255 integer registers", templ.name))?;
        Ok(TemplateCode {
            instrs: std::mem::take(&mut self.instrs),
            num_field_regs,
            num_int_regs,
            num_vars: u32::try_from(templ.var_stack_depth)?,
            input_signals: u32::try_from(templ.number_of_inputs)?,
            output_signals: u32::try_from(templ.number_of_outputs)?,
            sub_components: u32::try_from(templ.number_of_components)?,
            mappings,
            name_id: self.names.intern(&templ.name),
            symbol_id: self.names.intern(&templ.header),
        })
    }

    /// Lowers one function body into a [`FunctionCode`], resetting per-body state first
    /// (the same [`Self::reset_body`] a template uses — a fresh [`Env`]/[`RegAlloc`]
    /// pair, and every other per-body tracking field, per its own doc comment).
    ///
    /// Unlike [`Self::lower_template`], **no trailing instruction is appended**: a
    /// template's body always ends in `Instr::Return` because circom's front end never
    /// emits one itself (a template can fall off the end of its constraints), but a
    /// function's body always ends in an explicit `return` in valid circom source (the
    /// front end's own type checker rejects a function with a code path that doesn't
    /// return), so old's `ReturnSharedIfFun` trailer — the fallback for a function whose
    /// *only* executed `Ret`s were under a shared predicate — is exactly
    /// `circom_mpc_vm2::exec::Machine::run_function`'s fall-off-end path (see its own
    /// doc comment): falling off the end with a non-empty shared-return accumulator
    /// merges it, matching old byte for byte, with no separate opcode needed here.
    ///
    /// `num_params` is computed exactly as old (`circom-mpc-compiler/src/lib.rs:717-721`):
    /// the sum of every parameter's total element count (a scalar parameter contributes
    /// `1`, an array parameter the product of its dimensions) — this is also the number
    /// of `vars[0..num_params]` slots [`circom_mpc_vm2::exec::Machine::run_function`]
    /// overwrites with the call's arguments before running the body.
    fn lower_function(&mut self, fun: &FunctionCodeInfo) -> Result<FunctionCode> {
        self.reset_body();
        for inst in fun.body.iter() {
            stmt::lower_stmt(self, inst)?;
        }
        let num_field_regs = self
            .regs
            .high_water()
            .try_into()
            .map_err(|_| eyre!("function {} exceeds 65535 field registers", fun.name))?;
        let num_int_regs = self
            .iregs
            .high_water()
            .try_into()
            .map_err(|_| eyre!("function {} exceeds 255 integer registers", fun.name))?;
        let num_params = u32::try_from(
            fun.params
                .iter()
                .map(|p| p.length.iter().product::<usize>())
                .sum::<usize>(),
        )?;
        Ok(FunctionCode {
            instrs: std::mem::take(&mut self.instrs),
            num_field_regs,
            num_int_regs,
            num_vars: u32::try_from(fun.max_number_of_vars)?,
            num_params,
            name_id: self.names.intern(&fun.name),
        })
    }
}

/// A short, human-readable name for an [`Instruction`] variant, used in "not yet
/// lowered"/"unexpected instruction" error messages across [`expr`] and [`stmt`].
pub(crate) fn instr_kind_name(inst: &Instruction) -> &'static str {
    match inst {
        Instruction::Value(_) => "Value",
        Instruction::Load(_) => "Load",
        Instruction::Store(_) => "Store",
        Instruction::Compute(_) => "Compute",
        Instruction::Call(_) => "Call",
        Instruction::Branch(_) => "Branch",
        Instruction::Return(_) => "Return",
        Instruction::Assert(_) => "Assert",
        Instruction::Log(_) => "Log",
        Instruction::Loop(_) => "Loop",
        Instruction::CreateCmp(_) => "CreateCmp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_interner_reuses_ids_for_repeated_strings() {
        let mut names = NameInterner::default();
        assert_eq!(names.intern("a"), 0);
        assert_eq!(names.intern("b"), 1);
        assert_eq!(names.intern("a"), 0, "repeated string must reuse its id");
        assert_eq!(names.into_names(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn alloc_ireg_errors_past_255() {
        let config = CompilerConfig::default();
        let mut cg = CodeGen::<ark_bn254::Fr>::new(&config);
        for _ in 0..256 {
            cg.alloc_ireg().unwrap();
        }
        let err = cg.alloc_ireg().unwrap_err();
        assert!(
            err.to_string().contains("255 integer registers"),
            "error message should mention the register budget, got: {err}"
        );
    }
}

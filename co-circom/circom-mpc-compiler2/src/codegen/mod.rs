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
//! This task (Task 2) implements straight-line lowering only: `ComputeBucket`,
//! constant-address `LoadBucket`/`StoreBucket`, and the template body driver. Every
//! other bucket kind is a `bail!("not yet lowered: ...")` stub, filled in by its own
//! task — see the crate's task plan for the breakdown.
use crate::CompilerConfig;
use crate::frontend::OutputMapping;
use ark_ff::PrimeField;
use circom_compiler::circuit_design::template::TemplateCodeInfo;
use circom_compiler::compiler_interface::Circuit as CircomCircuit;
use circom_compiler::intermediate_representation::ir_interface::Instruction;
use circom_mpc_vm2::isa::{FnId, Instr, TemplId};
use circom_mpc_vm2::program::{CompiledProgram, DebugInfo, FunctionCode, InputInfo, TemplateCode};
use eyre::{Result, bail, eyre};
use std::collections::HashMap;

mod env;
mod expr;
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
    let strings = circuit.c_producer.get_string_table().clone();

    // Function bodies are skeleton-only until Task 7: rather than silently emitting an
    // incomplete/empty function table, bail loudly if the circuit actually declares any.
    if !circuit.functions.is_empty() {
        bail!(
            "not yet lowered: {} function(s) defined in this circuit \
             (full support lands in Task 7)",
            circuit.functions.len()
        );
    }

    // Phase 2: lower every template body.
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
        functions: Vec::<FunctionCode>::new(),
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
    /// The compiler configuration.
    pub(crate) config: &'c CompilerConfig,
    /// The instruction stream of the body currently being lowered.
    pub(crate) instrs: Vec<Instr>,
    /// Field-register allocator for the body currently being lowered.
    pub(crate) regs: RegAlloc,
    /// Integer-register allocator for the body currently being lowered.
    pub(crate) iregs: RegAlloc,
    /// Variable-binding environment for the body currently being lowered.
    ///
    /// Unused until Task 4 (every variable access this task arrives as a constant,
    /// component-relative address already, same as signals — see [`expr`]).
    #[allow(dead_code)]
    pub(crate) env: Env,
}

impl<'c, F: PrimeField> CodeGen<'c, F> {
    /// Creates a fresh, empty codegen state.
    fn new(config: &'c CompilerConfig) -> Self {
        Self {
            templ_ids: HashMap::new(),
            fn_ids: HashMap::new(),
            names: NameInterner::default(),
            constants: Vec::new(),
            config,
            instrs: Vec::new(),
            regs: RegAlloc::default(),
            iregs: RegAlloc::default(),
            env: Env,
        }
    }

    /// Resets the per-body state before lowering a new template/function.
    fn reset_body(&mut self) {
        self.instrs.clear();
        self.regs = RegAlloc::default();
        self.iregs = RegAlloc::default();
        self.env = Env;
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
}

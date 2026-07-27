//! Measurement helpers for deciding whether basic-block protocol batching is worthwhile.

use crate::driver::{CodeBody, InstructionSite};
use crate::isa::{BinOp, Instr};
use crate::program::CompiledProgram;
use ark_ff::PrimeField;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Rep3 operations for which [`VmDriver::bin_many`](crate::driver::VmDriver::bin_many)
/// has a real vector protocol rather than the scalar default.
pub fn rep3_vectorizable(op: BinOp) -> bool {
    matches!(op, BinOp::Mul | BinOp::BoolAnd | BinOp::Eq | BinOp::Neq)
}

/// Kind of profiled driver invocation at an instruction site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InteractionKind {
    /// A scalar binary operation.
    Bin(BinOp),
    /// A vector binary operation, already represented by `BinN` bytecode.
    BinN(BinOp),
    /// Any other Rep3 operation that requires communication.
    Other,
}

/// Aggregated calls and interactive lanes for one site and operation kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InteractionStats {
    /// Number of driver invocations containing at least one interactive lane.
    pub calls: u64,
    /// Number of interactive scalar lanes across those calls.
    pub lanes: u64,
}

/// Dynamic Rep3 communication census collected by a profiling
/// [`TaintDriver`](crate::drivers::taint::TaintDriver).
#[derive(Debug, Clone, Default)]
pub struct Rep3InteractionProfile {
    sites: BTreeMap<(InstructionSite, InteractionKind), InteractionStats>,
    unattributed: BTreeMap<InteractionKind, InteractionStats>,
}

impl Rep3InteractionProfile {
    pub(crate) fn record(
        &mut self,
        site: Option<InstructionSite>,
        kind: InteractionKind,
        lanes: usize,
    ) {
        if lanes == 0 {
            return;
        }
        let stats = match site {
            Some(site) => self.sites.entry((site, kind)).or_default(),
            None => self.unattributed.entry(kind).or_default(),
        };
        stats.calls += 1;
        stats.lanes += lanes as u64;
    }

    /// Returns the counters for `kind` at `site`, or zeroes if it never communicated.
    pub fn at(&self, site: InstructionSite, kind: InteractionKind) -> InteractionStats {
        self.sites.get(&(site, kind)).copied().unwrap_or_default()
    }

    /// Total interactive driver invocations, including VM-internal work without a
    /// direct bytecode site (for example a pending-write flush).
    pub fn total_calls(&self) -> u64 {
        self.sites
            .values()
            .chain(self.unattributed.values())
            .map(|stats| stats.calls)
            .sum()
    }

    /// Total interactive scalar lanes across all recorded driver invocations.
    pub fn total_lanes(&self) -> u64 {
        self.sites
            .values()
            .chain(self.unattributed.values())
            .map(|stats| stats.lanes)
            .sum()
    }
}

/// Bytecode-only census. Counts here are instruction definitions, not runtime
/// executions; use [`dynamic_batchability`] with a taint trace for Rep3-weighted data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StaticBatchability {
    /// Number of template bodies.
    pub templates: u64,
    /// Number of function bodies.
    pub functions: u64,
    /// Total bytecode instructions.
    pub instructions: u64,
    /// Scalar `Bin` instructions supported by Rep3's vector protocol.
    pub vectorizable_scalar_calls: u64,
    /// Per-operation breakdown of [`Self::vectorizable_scalar_calls`].
    pub vectorizable_scalar_by_op: VectorizableCalls,
    /// Existing `BinN` instructions supported by Rep3's vector protocol.
    pub existing_vector_calls: u64,
    /// Lanes covered by those existing `BinN` instructions.
    pub existing_vector_lanes: u64,
    /// Calls in immediately-adjacent, same-operation groups of at least two.
    pub adjacent_calls_before: u64,
    /// Vector calls required after batching those adjacent groups.
    pub adjacent_calls_after: u64,
    /// Calls in same-operation groups within one conservative basic block.
    pub block_calls_before: u64,
    /// Vector calls required by the same-block upper bound.
    pub block_calls_after: u64,
    /// Number of `EqN` instructions.
    pub eqn_instructions: u64,
    /// Total elements compared by `EqN` instructions.
    pub eqn_lanes: u64,
    /// Statically-created component instances across all body definitions.
    pub created_components: u64,
    /// Sites that feed subcomponent inputs and may synchronously run a component.
    pub input_sub_sites: u64,
}

/// Rep3-weighted runtime census from a taint execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DynamicBatchability {
    /// All interactive driver invocations observed in the run.
    pub interactive_calls: u64,
    /// Interactive scalar lanes, including already-vectorized calls.
    pub interactive_lanes: u64,
    /// Interactive scalar `Bin` calls supported by Rep3 vector protocols.
    pub vectorizable_scalar_calls: u64,
    /// Per-operation breakdown of [`Self::vectorizable_scalar_calls`].
    pub vectorizable_scalar_by_op: VectorizableCalls,
    /// Existing interactive `BinN` calls.
    pub existing_vector_calls: u64,
    /// Interactive lanes in existing `BinN` calls.
    pub existing_vector_lanes: u64,
    /// Interactive calls in immediately-adjacent same-op groups.
    pub adjacent_calls_before: u64,
    /// Calls after batching those adjacent groups.
    pub adjacent_calls_after: u64,
    /// Interactive calls in same-op groups within one conservative basic block.
    pub block_calls_before: u64,
    /// Calls required by the same-block upper bound.
    pub block_calls_after: u64,
}

/// Call counts for the four binary operations with real Rep3 vector protocols.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VectorizableCalls {
    /// Shared-by-shared multiplications.
    pub mul: u64,
    /// Shared-by-shared boolean ANDs.
    pub bool_and: u64,
    /// Equalities with at least one shared operand.
    pub eq: u64,
    /// Inequalities with at least one shared operand.
    pub neq: u64,
}

impl VectorizableCalls {
    fn add(&mut self, op: BinOp, count: u64) {
        match op {
            BinOp::Mul => self.mul += count,
            BinOp::BoolAnd => self.bool_and += count,
            BinOp::Eq => self.eq += count,
            BinOp::Neq => self.neq += count,
            _ => debug_assert!(false, "non-vectorizable Rep3 operation"),
        }
    }
}

/// Performs the bytecode-only batchability census.
pub fn static_batchability<F: PrimeField>(program: &CompiledProgram<F>) -> StaticBatchability {
    let mut report = StaticBatchability {
        templates: program.templates.len() as u64,
        functions: program.functions.len() as u64,
        ..Default::default()
    };
    for template in &program.templates {
        analyze_static_body(&template.instrs, &mut report);
    }
    for function in &program.functions {
        analyze_static_body(&function.instrs, &mut report);
    }
    report
}

/// Combines compiled bytecode structure with a taint trace to estimate the Rep3 call
/// reduction available without crossing a function, component, or control-flow barrier.
/// `adjacent_*` is the ceiling for a same-op peephole (before dependency checks), while
/// `block_*` is the ceiling available to a dependency-aware basic-block scheduler.
pub fn dynamic_batchability<F: PrimeField>(
    program: &CompiledProgram<F>,
    profile: &Rep3InteractionProfile,
) -> DynamicBatchability {
    let mut report = DynamicBatchability {
        interactive_calls: profile.total_calls(),
        interactive_lanes: profile.total_lanes(),
        ..Default::default()
    };
    for (idx, template) in program.templates.iter().enumerate() {
        analyze_dynamic_body(
            CodeBody::Template(crate::isa::TemplId(idx as u32)),
            &template.instrs,
            profile,
            &mut report,
        );
    }
    for (idx, function) in program.functions.iter().enumerate() {
        analyze_dynamic_body(
            CodeBody::Function(crate::isa::FnId(idx as u32)),
            &function.instrs,
            profile,
            &mut report,
        );
    }
    report
}

fn analyze_static_body(instrs: &[Instr], report: &mut StaticBatchability) {
    report.instructions += instrs.len() as u64;
    for instr in instrs {
        match instr {
            Instr::Bin { op, .. } if rep3_vectorizable(*op) => {
                report.vectorizable_scalar_calls += 1;
                report.vectorizable_scalar_by_op.add(*op, 1);
            }
            Instr::BinN { op, n, .. } if rep3_vectorizable(*op) => {
                report.existing_vector_calls += 1;
                report.existing_vector_lanes += *n as u64;
            }
            Instr::BinBatch { op, lanes } if rep3_vectorizable(*op) => {
                report.existing_vector_calls += 1;
                report.existing_vector_lanes += lanes.len() as u64;
            }
            Instr::EqN { n, .. } => {
                report.eqn_instructions += 1;
                report.eqn_lanes += *n as u64;
            }
            Instr::CreateCmp { count, .. } => report.created_components += *count as u64,
            Instr::InputSub { .. } => report.input_sub_sites += 1,
            _ => {}
        }
    }

    for (start, end) in basic_blocks(instrs) {
        let block = &instrs[start..end];
        accumulate_static_adjacent(block, report);
        let mut counts = BTreeMap::<BinOp, u64>::new();
        for instr in block {
            if let Instr::Bin { op, .. } = instr
                && rep3_vectorizable(*op)
            {
                *counts.entry(*op).or_default() += 1;
            }
        }
        for count in counts.into_values().filter(|count| *count >= 2) {
            report.block_calls_before += count;
            report.block_calls_after += 1;
        }
    }
}

fn accumulate_static_adjacent(block: &[Instr], report: &mut StaticBatchability) {
    let mut run_op = None;
    let mut run_len = 0u64;
    let flush = |len: u64, report: &mut StaticBatchability| {
        if len >= 2 {
            report.adjacent_calls_before += len;
            report.adjacent_calls_after += 1;
        }
    };
    for instr in block {
        let op = match instr {
            Instr::Bin { op, .. } if rep3_vectorizable(*op) => Some(*op),
            _ => None,
        };
        if op.is_some() && op == run_op {
            run_len += 1;
        } else {
            flush(run_len, report);
            run_op = op;
            run_len = u64::from(op.is_some());
        }
    }
    flush(run_len, report);
}

fn analyze_dynamic_body(
    body: CodeBody,
    instrs: &[Instr],
    profile: &Rep3InteractionProfile,
    report: &mut DynamicBatchability,
) {
    for (ip, instr) in instrs.iter().enumerate() {
        let site = InstructionSite {
            body,
            ip: ip as u32,
        };
        match instr {
            Instr::Bin { op, .. } if rep3_vectorizable(*op) => {
                let calls = profile.at(site, InteractionKind::Bin(*op)).calls;
                report.vectorizable_scalar_calls += calls;
                report.vectorizable_scalar_by_op.add(*op, calls);
            }
            Instr::BinN { op, .. } | Instr::BinBatch { op, .. } if rep3_vectorizable(*op) => {
                let stats = profile.at(site, InteractionKind::BinN(*op));
                report.existing_vector_calls += stats.calls;
                report.existing_vector_lanes += stats.lanes;
            }
            _ => {}
        }
    }

    for (start, end) in basic_blocks(instrs) {
        accumulate_dynamic_adjacent(body, start, &instrs[start..end], profile, report);
        let mut counts = BTreeMap::<BinOp, Vec<u64>>::new();
        for (offset, instr) in instrs[start..end].iter().enumerate() {
            if let Instr::Bin { op, .. } = instr
                && rep3_vectorizable(*op)
            {
                let site = InstructionSite {
                    body,
                    ip: (start + offset) as u32,
                };
                let calls = profile.at(site, InteractionKind::Bin(*op)).calls;
                if calls > 0 {
                    counts.entry(*op).or_default().push(calls);
                }
            }
        }
        for calls in counts.into_values().filter(|calls| calls.len() >= 2) {
            report.block_calls_before += calls.iter().sum::<u64>();
            report.block_calls_after += calls.into_iter().max().unwrap_or(0);
        }
    }
}

fn accumulate_dynamic_adjacent(
    body: CodeBody,
    start: usize,
    block: &[Instr],
    profile: &Rep3InteractionProfile,
    report: &mut DynamicBatchability,
) {
    let mut run_op = None;
    let mut calls = Vec::new();
    let flush = |calls: &mut Vec<u64>, report: &mut DynamicBatchability| {
        if calls.len() >= 2 {
            report.adjacent_calls_before += calls.iter().sum::<u64>();
            report.adjacent_calls_after += calls.iter().copied().max().unwrap_or(0);
        }
        calls.clear();
    };
    for (offset, instr) in block.iter().enumerate() {
        let op = match instr {
            Instr::Bin { op, .. } if rep3_vectorizable(*op) => Some(*op),
            _ => None,
        };
        if op != run_op {
            flush(&mut calls, report);
            run_op = op;
        }
        if let Some(op) = op {
            let site = InstructionSite {
                body,
                ip: (start + offset) as u32,
            };
            let count = profile.at(site, InteractionKind::Bin(op)).calls;
            if count == 0 {
                flush(&mut calls, report);
                run_op = None;
            } else {
                calls.push(count);
            }
        }
    }
    flush(&mut calls, report);
}

fn basic_blocks(instrs: &[Instr]) -> Vec<(usize, usize)> {
    if instrs.is_empty() {
        return Vec::new();
    }
    let mut leaders = BTreeSet::from([0usize, instrs.len()]);
    for (ip, instr) in instrs.iter().enumerate() {
        let next = ip + 1;
        match instr {
            Instr::Jmp { target } | Instr::JmpIfZero { target, .. } => {
                leaders.insert(*target as usize);
                leaders.insert(next);
            }
            Instr::SharedIf { else_target, .. } | Instr::SharedIfBit { else_target, .. } => {
                leaders.insert(*else_target as usize);
                leaders.insert(next);
            }
            Instr::SharedElse { end_target } => {
                leaders.insert(*end_target as usize);
                leaders.insert(next);
            }
            Instr::CallFn { .. }
            | Instr::CreateCmp { .. }
            | Instr::InputSub { .. }
            | Instr::Ret { .. }
            | Instr::Return => {
                leaders.insert(ip);
                leaders.insert(next);
            }
            _ => {}
        }
    }
    let leaders: Vec<_> = leaders
        .into_iter()
        .filter(|leader| *leader <= instrs.len())
        .collect();
    leaders
        .windows(2)
        .filter_map(|pair| (pair[0] < pair[1]).then_some((pair[0], pair[1])))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::taint::{Taint, TaintDriver};
    use crate::exec::Machine;
    use crate::isa::{Src, TemplId};
    use crate::program::{CompiledProgram, DebugInfo, TemplateCode, VMConfig};

    fn bin(op: BinOp, dst: u16) -> Instr {
        Instr::Bin {
            op,
            dst,
            a: Src::Reg(0),
            b: Src::Reg(1),
        }
    }

    fn program(instrs: Vec<Instr>) -> CompiledProgram<ark_bn254::Fr> {
        CompiledProgram {
            templates: vec![TemplateCode {
                instrs,
                num_field_regs: 3,
                num_int_regs: 0,
                num_vars: 0,
                input_signals: 0,
                output_signals: 0,
                intermediate_signals: 0,
                sub_components: 0,
                mappings: vec![],
                name_id: 0,
                symbol_id: 0,
            }],
            functions: vec![],
            constants: vec![],
            strings: vec![],
            main: TemplId(0),
            total_signals: 1,
            main_inputs: 0,
            main_outputs: 0,
            main_input_list: vec![],
            output_mapping: Default::default(),
            signal_to_witness: vec![0],
            public_inputs: vec![],
            debug: DebugInfo::default(),
        }
    }

    #[test]
    fn static_report_separates_adjacent_and_block_upper_bound() {
        let program = program(vec![
            bin(BinOp::Mul, 0),
            Instr::Neg {
                dst: 2,
                a: Src::Reg(0),
            },
            bin(BinOp::Mul, 1),
            bin(BinOp::Mul, 2),
            Instr::Return,
        ]);
        let report = static_batchability(&program);
        assert_eq!(report.vectorizable_scalar_calls, 3);
        assert_eq!(report.adjacent_calls_before, 2);
        assert_eq!(report.adjacent_calls_after, 1);
        assert_eq!(report.block_calls_before, 3);
        assert_eq!(report.block_calls_after, 1);
    }

    #[test]
    fn taint_trace_weights_only_rep3_interactive_calls() {
        let mut program = program(vec![
            Instr::Bin {
                op: BinOp::Mul,
                dst: 0,
                a: Src::Signal(crate::isa::Addr::Const(0)),
                b: Src::Signal(crate::isa::Addr::Const(1)),
            },
            Instr::Bin {
                op: BinOp::Mul,
                dst: 1,
                a: Src::Signal(crate::isa::Addr::Const(0)),
                b: Src::Signal(crate::isa::Addr::Const(1)),
            },
            Instr::Return,
        ]);
        program.templates[0].input_signals = 2;
        program.total_signals = 3;
        program.debug.names.push("Main".into());

        let mut driver = TaintDriver::profiling();
        {
            let mut machine = Machine::new(&program, &mut driver, VMConfig::default()).unwrap();
            machine.signals[1] = Taint {
                val: ark_bn254::Fr::from(2u64),
                shared: true,
            };
            machine.signals[2] = Taint {
                val: ark_bn254::Fr::from(3u64),
                shared: true,
            };
            machine.run_main().unwrap();
        }
        let report = dynamic_batchability(
            &program,
            driver.interaction_profile().expect("profiling is enabled"),
        );
        assert_eq!(report.interactive_calls, 2);
        assert_eq!(report.vectorizable_scalar_calls, 2);
        assert_eq!(
            report.adjacent_calls_before - report.adjacent_calls_after,
            1
        );
        assert_eq!(report.block_calls_before - report.block_calls_after, 1);
    }
}

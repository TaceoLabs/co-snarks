//! Post-lowering bytecode passes.
//!
//! Lowering emits absolute instruction targets, so any pass that removes instructions
//! must update every control-flow target in the body. This module owns that bookkeeping:
//! passes describe which old instructions survive and [`compact`] rebuilds the body and
//! remaps all targets through old instruction boundaries. Keeping target rewriting here
//! avoids each optimization growing a subtly different jump-fixup implementation.

use circom_mpc_vm2::isa::Instr;
use eyre::{Result, bail, eyre};

/// Runs the post-lowering pipeline for one template or function body.
///
/// The initial pipeline is deliberately semantics-neutral: it constructs and validates
/// the CFG that subsequent folding, DCE, and scheduling passes consume. Having every body
/// cross this boundary now means those passes can be added without changing codegen's
/// template/function finalization paths independently.
pub(super) fn run(instrs: Vec<Instr>, body_name: &str) -> Result<Vec<Instr>> {
    let cfg = ControlFlowGraph::build(&instrs)
        .map_err(|error| eyre!("invalid bytecode for {body_name}: {error}"))?;
    tracing::trace!(
        body = body_name,
        instructions = instrs.len(),
        basic_blocks = cfg.blocks.len(),
        cfg_edges = cfg.edge_count(),
        "ran post-lowering bytecode passes"
    );
    Ok(instrs)
}

/// A maximal straight-line instruction range and its possible successors.
#[derive(Debug, PartialEq, Eq)]
struct BasicBlock {
    start: usize,
    end: usize,
    successors: Vec<Successor>,
}

/// A CFG edge either enters another basic block or leaves the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Successor {
    Block(usize),
    Exit,
}

/// Control-flow view of a lowered body.
#[derive(Debug, PartialEq, Eq)]
struct ControlFlowGraph {
    blocks: Vec<BasicBlock>,
}

impl ControlFlowGraph {
    fn build(instrs: &[Instr]) -> Result<Self> {
        validate_targets(instrs)?;
        if instrs.is_empty() {
            return Ok(Self { blocks: Vec::new() });
        }

        // A dense marker array is linear and cache-friendly. Bytecode bodies are dense
        // instruction vectors, so a tree/set of sparse leaders only adds allocations
        // and pointer chasing here.
        let mut leaders = vec![false; instrs.len() + 1];
        leaders[0] = true;
        leaders[instrs.len()] = true;
        for (ip, instr) in instrs.iter().enumerate() {
            if let Some(target) = target(instr) {
                leaders[target as usize] = true;
            }
            if is_block_terminator(instr) {
                leaders[ip + 1] = true;
            }
        }
        let leaders = leaders
            .into_iter()
            .enumerate()
            .filter_map(|(ip, is_leader)| is_leader.then_some(ip))
            .collect::<Vec<_>>();
        let mut block_at = vec![usize::MAX; instrs.len()];
        for (block, range) in leaders.windows(2).enumerate() {
            for slot in &mut block_at[range[0]..range[1]] {
                *slot = block;
            }
        }

        let mut blocks = Vec::with_capacity(leaders.len() - 1);
        for range in leaders.windows(2) {
            let start = range[0];
            let end = range[1];
            if start == end {
                continue;
            }
            let successors = successors(instrs, end - 1, &block_at);
            blocks.push(BasicBlock {
                start,
                end,
                successors,
            });
        }
        Ok(Self { blocks })
    }

    fn edge_count(&self) -> usize {
        self.blocks.iter().map(|block| block.successors.len()).sum()
    }
}

fn validate_targets(instrs: &[Instr]) -> Result<()> {
    for (ip, instr) in instrs.iter().enumerate() {
        let Some(target) = target(instr) else {
            continue;
        };
        if target as usize > instrs.len() {
            bail!(
                "instruction {ip} targets {target}, past body length {}",
                instrs.len()
            );
        }
    }
    Ok(())
}

fn is_block_terminator(instr: &Instr) -> bool {
    matches!(
        instr,
        Instr::Jmp { .. }
            | Instr::JmpIfZero { .. }
            | Instr::SharedIf { .. }
            | Instr::SharedIfBit { .. }
            | Instr::SharedElse { .. }
            | Instr::Ret { .. }
            | Instr::Return
    )
}

fn successors(instrs: &[Instr], ip: usize, block_at: &[usize]) -> Vec<Successor> {
    let fallthrough = || successor(ip + 1, block_at);
    let jump = |target: u32| successor(target as usize, block_at);
    match &instrs[ip] {
        Instr::Jmp { target } => vec![jump(*target)],
        Instr::JmpIfZero { target, .. }
        | Instr::SharedIf {
            else_target: target,
            ..
        }
        | Instr::SharedIfBit {
            else_target: target,
            ..
        }
        | Instr::SharedElse { end_target: target } => {
            let mut edges = vec![fallthrough(), jump(*target)];
            edges.dedup();
            edges
        }
        // A Ret exits when executed publicly, but accumulates and falls through under a
        // shared predicate. Keep both edges so data-flow passes remain conservative.
        Instr::Ret { .. } => {
            let mut edges = vec![Successor::Exit, fallthrough()];
            edges.dedup();
            edges
        }
        Instr::Return => vec![Successor::Exit],
        _ => vec![fallthrough()],
    }
}

fn successor(ip: usize, block_at: &[usize]) -> Successor {
    block_at
        .get(ip)
        .copied()
        .map(Successor::Block)
        .unwrap_or(Successor::Exit)
}

fn target(instr: &Instr) -> Option<u32> {
    match instr {
        Instr::Jmp { target } | Instr::JmpIfZero { target, .. } => Some(*target),
        Instr::SharedIf { else_target, .. } | Instr::SharedIfBit { else_target, .. } => {
            Some(*else_target)
        }
        Instr::SharedElse { end_target } => Some(*end_target),
        _ => None,
    }
}

fn target_mut(instr: &mut Instr) -> Option<&mut u32> {
    match instr {
        Instr::Jmp { target } | Instr::JmpIfZero { target, .. } => Some(target),
        Instr::SharedIf { else_target, .. } | Instr::SharedIfBit { else_target, .. } => {
            Some(else_target)
        }
        Instr::SharedElse { end_target } => Some(end_target),
        _ => None,
    }
}

/// Removes instructions for which `keep[old_ip]` is false and remaps every absolute
/// target. A target of a removed instruction lands on the next surviving instruction;
/// a target at the old end of the body lands at the new end.
///
/// This deletion-only primitive is sufficient for unreachable-block cleanup and DCE.
/// Passes that replace an instruction in place can mutate it before calling `compact`.
#[allow(dead_code)] // Used by the first mutating passes; kept exercised by unit tests now.
fn compact(instrs: Vec<Instr>, keep: &[bool]) -> Result<Vec<Instr>> {
    if instrs.len() != keep.len() {
        bail!(
            "keep map length {} does not match body length {}",
            keep.len(),
            instrs.len()
        );
    }
    validate_targets(&instrs)?;

    // `boundaries[old_ip]` is the new instruction boundary immediately before the old
    // instruction. It also contains the one-past-the-end boundary at `old_len`.
    let mut boundaries = Vec::with_capacity(instrs.len() + 1);
    let mut new_ip = 0usize;
    for &survives in keep {
        boundaries.push(new_ip);
        new_ip += usize::from(survives);
    }
    boundaries.push(new_ip);

    let mut out = Vec::with_capacity(new_ip);
    for (mut instr, survives) in instrs.into_iter().zip(keep.iter().copied()) {
        if !survives {
            continue;
        }
        if let Some(old_target) = target_mut(&mut instr) {
            *old_target = u32::try_from(boundaries[*old_target as usize])
                .map_err(|_| eyre!("rewritten body exceeds u32::MAX instructions"))?;
        }
        out.push(instr);
    }
    validate_targets(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use circom_mpc_vm2::isa::{Dst, RetSrc, Src};

    #[test]
    fn cfg_models_conditional_and_ret_fallthrough() {
        let instrs = vec![
            Instr::JmpIfZero {
                cond: Src::Reg(0),
                target: 3,
            },
            Instr::Ret {
                src: RetSrc::Reg(1),
                n: 1,
            },
            Instr::Jmp { target: 4 },
            Instr::Mov {
                dst: Dst::Reg(1),
                src: Src::Const(0),
            },
        ];

        let cfg = ControlFlowGraph::build(&instrs).unwrap();
        assert_eq!(cfg.blocks.len(), 4);
        assert_eq!(
            cfg.blocks[0].successors,
            vec![Successor::Block(1), Successor::Block(3)]
        );
        assert_eq!(
            cfg.blocks[1].successors,
            vec![Successor::Exit, Successor::Block(2)]
        );
        assert_eq!(cfg.blocks[2].successors, vec![Successor::Exit]);
        assert_eq!(cfg.blocks[3].successors, vec![Successor::Exit]);
    }

    #[test]
    fn rejects_target_past_end_of_body() {
        let error = run(vec![Instr::Jmp { target: 2 }], "bad").unwrap_err();
        assert!(error.to_string().contains("instruction 0 targets 2"));
    }

    #[test]
    fn compact_remaps_every_absolute_target_kind() {
        let instrs = vec![
            Instr::Jmp { target: 7 },
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Const(0),
            },
            Instr::JmpIfZero {
                cond: Src::Reg(0),
                target: 7,
            },
            Instr::SharedIf {
                cond: Src::Reg(0),
                else_target: 7,
            },
            Instr::SharedIfBit {
                cond: Src::Reg(0),
                else_target: 7,
            },
            Instr::SharedElse { end_target: 7 },
            Instr::Mov {
                dst: Dst::Reg(0),
                src: Src::Const(1),
            },
            Instr::Return,
        ];

        let out = compact(instrs, &[true, false, true, true, true, true, false, true]).unwrap();
        assert_eq!(
            out,
            vec![
                Instr::Jmp { target: 5 },
                Instr::JmpIfZero {
                    cond: Src::Reg(0),
                    target: 5,
                },
                Instr::SharedIf {
                    cond: Src::Reg(0),
                    else_target: 5,
                },
                Instr::SharedIfBit {
                    cond: Src::Reg(0),
                    else_target: 5,
                },
                Instr::SharedElse { end_target: 5 },
                Instr::Return,
            ]
        );
    }

    #[test]
    fn target_of_removed_instruction_advances_to_next_survivor() {
        let out = compact(
            vec![
                Instr::Jmp { target: 1 },
                Instr::Mov {
                    dst: Dst::Reg(0),
                    src: Src::Const(0),
                },
                Instr::Return,
            ],
            &[true, false, true],
        )
        .unwrap();
        assert_eq!(out, vec![Instr::Jmp { target: 1 }, Instr::Return]);
    }
}

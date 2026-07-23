//! The execution engine.
//!
//! [`Machine`] owns the signal RAM and the constant table for one witness extension and
//! drives the register-VM dispatch loop over a [`CompiledProgram`]. This module
//! currently implements the straight-line, integer-unit, jump, and shared-if
//! instruction subset (see [`Predication`]); function calls and subcomponents are
//! added by later tasks (instructions outside this task's subset produce a "not yet
//! implemented" error).
use crate::driver::{VmDriver, apply_bin};
use crate::isa::*;
use crate::program::{CompiledProgram, TemplateCode, VMConfig};
use ark_ff::PrimeField;
use eyre::{Result, bail};

/// Per-activation register frame.
pub struct Frame<T> {
    /// Field-register file (expression temporaries).
    pub regs: Vec<T>,
    /// Integer-register file (loop/addressing indices).
    pub iregs: Vec<usize>,
    /// Local variable slots.
    pub vars: Vec<T>,
}

impl<T: Default + Clone> Frame<T> {
    /// Allocate a fresh, zeroed frame sized for `t`.
    fn for_template(t: &TemplateCode) -> Self {
        Self {
            regs: vec![T::default(); t.num_field_regs as usize],
            iregs: vec![0; t.num_int_regs as usize],
            vars: vec![T::default(); t.num_vars as usize],
        }
    }
}

/// A component instance (template activation in the signal tree).
pub struct ComponentInst {
    /// The template this instance runs.
    pub templ: TemplId,
    /// Signal-RAM offset of this instance (absolute).
    pub offset: usize,
    /// Number of input values received so far (drives run-on-last-input for
    /// subcomponents; unused until `InputSub` is implemented).
    pub provided_inputs: u32,
    /// Child component instances, indexed as created by `CreateCmp`.
    pub sub: Vec<ComponentInst>,
}

/// One level of the [`Predication`] stack.
enum PredLevel<T> {
    /// A public-condition `if`: the executor takes a real jump, no cmux needed.
    Public,
    /// A shared-condition `if`: both branches execute, stores are cmux'd.
    Shared {
        /// `acc` of the enclosing shared level at push time (`public_one` if none).
        outer_acc: T,
        /// Combined condition: `and(outer_acc, cur)`, resp. `and(outer_acc, !cur)`
        /// after [`Predication::toggle`].
        acc: T,
        /// This level's raw (un-combined) condition.
        cur: T,
        /// The `cached` value to restore when this level is popped.
        prev_cached: Option<T>,
    },
}

/// Runtime predication state for shared ifs. Lives per component run and is shared by
/// nested function frames (matches the old per-`Component` `if_stack`; Task 6 threads
/// the same instance through function calls).
pub struct Predication<T: Clone> {
    /// The stack of active `if` levels, outermost first.
    levels: Vec<PredLevel<T>>,
    /// Number of [`PredLevel::Shared`] levels currently on the stack — kept in sync
    /// with `levels` so [`Predication::is_shared`] is O(1).
    shared_depth: usize,
    /// Combined condition of the innermost shared level (already accumulates all
    /// outer shared levels). `None` ⇔ no shared level is active.
    cached: Option<T>,
}

impl<T: Clone> Predication<T> {
    /// A fresh predication state: no active levels, no shared condition.
    pub fn new() -> Self {
        Self {
            levels: Vec::new(),
            shared_depth: 0,
            cached: None,
        }
    }

    /// Push a shared-if level for `cond`, combining it with the enclosing shared
    /// level's accumulated condition (or `public_one` if none is active). Mirrors old
    /// `IfCtxStack::push_shared` (`circom-mpc-vm/src/mpc_vm.rs:166-185`).
    pub fn push_shared<F, C>(&mut self, driver: &mut C, cond: T) -> Result<()>
    where
        F: PrimeField,
        C: VmDriver<F, VmType = T>,
    {
        let outer_acc = self.cached.clone().unwrap_or_else(|| driver.public_one());
        let acc = driver.bool_and(&outer_acc, &cond)?;
        let prev_cached = self.cached.take();
        self.cached = Some(acc.clone());
        self.levels.push(PredLevel::Shared {
            outer_acc,
            acc,
            cur: cond,
            prev_cached,
        });
        self.shared_depth += 1;
        Ok(())
    }

    /// Push a public-if level: no predication state, the executor performs a real
    /// jump instead.
    pub fn push_public(&mut self) {
        self.levels.push(PredLevel::Public);
    }

    /// Toggle the condition of the top level (which must be [`PredLevel::Shared`]) to
    /// enter its else branch. Mirrors old `IfCtxStack::toggle_last_shared`
    /// (`circom-mpc-vm/src/mpc_vm.rs:187-200`) — the new compiler only emits
    /// `SharedElse` when the top level is the matching shared one, so operating on the
    /// top of the stack (rather than searching for the innermost shared level) is
    /// correct here.
    pub fn toggle<F, C>(&mut self, driver: &mut C) -> Result<()>
    where
        F: PrimeField,
        C: VmDriver<F, VmType = T>,
    {
        match self.levels.last_mut() {
            Some(PredLevel::Shared {
                outer_acc,
                acc,
                cur,
                ..
            }) => {
                let ncur = driver.bool_not(cur)?;
                let nacc = driver.bool_and(outer_acc, &ncur)?;
                *cur = ncur;
                *acc = nacc.clone();
                self.cached = Some(nacc);
                Ok(())
            }
            _ => bail!("Predication::toggle called with no shared level on top"),
        }
    }

    /// Pop the innermost level, restoring `cached` to the value it held before the
    /// matching push (a no-op for `cached` when the popped level is `Public`).
    pub fn pop(&mut self) {
        if let Some(PredLevel::Shared { prev_cached, .. }) = self.levels.pop() {
            self.cached = prev_cached;
            self.shared_depth -= 1;
        }
    }

    /// Whether the innermost level is [`PredLevel::Public`].
    pub fn top_is_public(&self) -> bool {
        matches!(self.levels.last(), Some(PredLevel::Public))
    }

    /// The combined condition of the innermost shared level, if any (O(1)).
    pub fn cond(&self) -> Option<&T> {
        self.cached.as_ref()
    }

    /// Whether any shared level is currently active (O(1)).
    pub fn is_shared(&self) -> bool {
        self.shared_depth > 0
    }
}

impl<T: Clone> Default for Predication<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The whole VM state during one witness extension.
pub struct Machine<'a, F: PrimeField, C: VmDriver<F>> {
    /// The compiled program being executed.
    pub program: &'a CompiledProgram<F>,
    /// The MPC (or plain) protocol driver.
    pub driver: &'a mut C,
    /// Signal RAM (index 0 is the constant 1).
    pub signals: Vec<C::VmType>,
    /// Field-constant table, mapped through the driver's `public_from`.
    pub consts: Vec<C::VmType>,
    /// VM configuration.
    pub config: VMConfig,
    /// Accumulated log output pending a `LogFlush`.
    pub log_buf: String,
}

impl<'a, F: PrimeField, C: VmDriver<F>> Machine<'a, F, C> {
    /// Allocate signal RAM, inject constants, place the constant 1 at signal 0.
    pub fn new(
        program: &'a CompiledProgram<F>,
        driver: &'a mut C,
        config: VMConfig,
    ) -> Result<Self> {
        let mut signals = vec![C::VmType::default(); program.total_signals];
        signals[0] = driver.public_one();
        let consts = program
            .constants
            .iter()
            .map(|f| driver.public_from(*f))
            .collect();
        Ok(Self {
            program,
            driver,
            signals,
            consts,
            config,
            log_buf: String::with_capacity(1024),
        })
    }

    /// Run the main component (inputs must already be written into signal RAM).
    pub fn run_main(&mut self) -> Result<()> {
        let mut main = ComponentInst {
            templ: self.program.main,
            offset: 1,
            provided_inputs: 0,
            sub: vec![],
        };
        self.run_component(&mut main)
    }

    /// Execute one template activation to completion (until `Return`).
    fn run_component(&mut self, comp: &mut ComponentInst) -> Result<()> {
        let code = &self.program.templates[comp.templ.0 as usize];
        let mut frame = Frame::for_template(code);
        // Fresh per component activation, matching the old per-`Component` `if_stack`;
        // Task 6 threads this same instance through any function calls made from here.
        let mut pred: Predication<C::VmType> = Predication::new();
        let mut ip: usize = 0;
        loop {
            let inst = &code.instrs[ip];
            match inst {
                Instr::Bin { op, dst, a, b } => {
                    let r = {
                        let a = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, a)?;
                        let b = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, b)?;
                        // Div guard: mirrors old mpc_vm.rs:614-622. Under a shared (possibly
                        // untaken) branch, a literal zero divisor must not error — replace it
                        // with 1 before dividing; the store that follows is still cmux'd
                        // against the old value, so the untaken branch's result is discarded.
                        if matches!(op, BinOp::Div) && pred.is_shared() {
                            let one = self.driver.public_one();
                            let cond = pred.cond().expect("is_shared implies cond is Some").clone();
                            let b = self.driver.cmux(&cond, b, &one)?;
                            self.driver.div(a, &b)?
                        } else {
                            apply_bin(self.driver, *op, a, b)?
                        }
                    };
                    frame.regs[*dst as usize] = r;
                }
                Instr::Neg { dst, a } => {
                    let r = {
                        let a = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, a)?;
                        self.driver.neg(a)?
                    };
                    frame.regs[*dst as usize] = r;
                }
                Instr::EqN { dst, a, b, n } => {
                    // Per-element eq, folded with bool_and, initial accumulator public_one —
                    // mirrors old circom-mpc-vm/src/mpc_vm.rs:663-679.
                    let mut result = self.driver.public_one();
                    for k in 0..*n as usize {
                        let av =
                            read_n::<F, C>(&frame, &self.signals, &self.consts, comp.offset, a, k)?
                                .clone();
                        let bv =
                            read_n::<F, C>(&frame, &self.signals, &self.consts, comp.offset, b, k)?
                                .clone();
                        let cmp = self.driver.eq(&av, &bv)?;
                        result = self.driver.bool_and(&cmp, &result)?;
                    }
                    frame.regs[*dst as usize] = result;
                }
                Instr::Mov { dst, src } => {
                    let v = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, src)?
                        .clone();
                    write_dst::<F, C>(
                        self.driver,
                        &pred,
                        &mut frame,
                        &mut self.signals,
                        comp.offset,
                        dst,
                        0,
                        v,
                    )?;
                }
                Instr::LoadN { dst, src, n } => {
                    // Consecutive reads from the source address; scatter into regs[dst..dst+n].
                    for k in 0..*n as usize {
                        let v = read_n::<F, C>(
                            &frame,
                            &self.signals,
                            &self.consts,
                            comp.offset,
                            src,
                            k,
                        )?
                        .clone();
                        frame.regs[*dst as usize + k] = v;
                    }
                }
                Instr::StoreN { dst, src, n } => {
                    // Consecutive predicated writes.
                    for k in 0..*n as usize {
                        let v = frame.regs[*src as usize + k].clone();
                        write_dst::<F, C>(
                            self.driver,
                            &pred,
                            &mut frame,
                            &mut self.signals,
                            comp.offset,
                            dst,
                            k,
                            v,
                        )?;
                    }
                }
                Instr::BinN { op, dst, a, b, n } => {
                    // Gather operands, one vectorized driver call, scatter results.
                    let n = *n as usize;
                    let mut av = Vec::with_capacity(n);
                    let mut bv = Vec::with_capacity(n);
                    for k in 0..n {
                        av.push(
                            read_n::<F, C>(&frame, &self.signals, &self.consts, comp.offset, a, k)?
                                .clone(),
                        );
                        bv.push(
                            read_n::<F, C>(&frame, &self.signals, &self.consts, comp.offset, b, k)?
                                .clone(),
                        );
                    }
                    // Div guard, vectorized: mirrors the scalar `Bin` guard above — under
                    // a shared (possibly untaken) branch, replace every divisor with 1
                    // before dividing, so a literal zero divisor in the untaken branch
                    // never errors.
                    let rv = if matches!(op, BinOp::Div) && pred.is_shared() {
                        let ones = vec![self.driver.public_one(); n];
                        let cond = pred.cond().expect("is_shared implies cond is Some").clone();
                        let guarded_b = self.driver.cmux_many(&cond, &bv, &ones)?;
                        self.driver.bin_many(*op, &av, &guarded_b)?
                    } else {
                        self.driver.bin_many(*op, &av, &bv)?
                    };
                    for (k, v) in rv.into_iter().enumerate() {
                        frame.regs[*dst as usize + k] = v;
                    }
                }
                Instr::ISet { dst, val } => frame.iregs[*dst as usize] = *val as usize,
                Instr::IAdd { dst, a, b } => {
                    frame.iregs[*dst as usize] = iread(&frame, a) + iread(&frame, b)
                }
                Instr::IMul { dst, a, b } => {
                    frame.iregs[*dst as usize] = iread(&frame, a) * iread(&frame, b)
                }
                Instr::ToIndex { dst, src } => {
                    let v = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, src)?
                        .clone();
                    frame.iregs[*dst as usize] = self.driver.to_index(&v)?;
                }
                Instr::Jmp { target } => {
                    ip = *target as usize;
                    continue;
                }
                Instr::JmpIfZero { cond, target } => {
                    let c = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, cond)?
                        .clone();
                    if self.driver.is_zero(&c, false)? {
                        ip = *target as usize;
                        continue;
                    }
                }
                Instr::SharedIf { cond, else_target } => {
                    // mirrors old mpc_vm.rs:562-576 (`MpcOpCode::If`).
                    let c = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, cond)?
                        .clone();
                    if self.driver.is_shared(&c)? {
                        pred.push_shared(self.driver, c)?;
                    } else {
                        pred.push_public();
                        if self.driver.is_zero(&c, false)? {
                            ip = *else_target as usize;
                            continue;
                        }
                    }
                }
                Instr::SharedElse { end_target } => {
                    // mirrors old mpc_vm.rs:577-592 (`MpcOpCode::EndTruthyBranch`): a public
                    // level jumps past the else branch straight to `SharedEnd` (still
                    // executing the pop); a shared level falls into the else branch with its
                    // condition toggled.
                    if pred.top_is_public() {
                        ip = *end_target as usize;
                        continue;
                    }
                    pred.toggle(self.driver)?;
                }
                Instr::SharedEnd => pred.pop(), // mirrors old mpc_vm.rs:593-598 (`EndFalsyBranch`).
                Instr::Return => break,
                Instr::Assert { cond, line } => {
                    let c = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, cond)?
                        .clone();
                    if self.driver.is_zero(&c, true)? {
                        bail!(
                            "Assertion failed during execution on line {line} in component {}",
                            self.program.debug.names[code.symbol_id as usize]
                        );
                    }
                }
                Instr::Log { src } => {
                    // mirrors old circom-mpc-vm/src/mpc_vm.rs:858-862.
                    let v = read::<F, C>(&frame, &self.signals, &self.consts, comp.offset, src)?
                        .clone();
                    let log = self.driver.log(&v, self.config.allow_leaky_logs)?;
                    self.log_buf.push_str(&log);
                    self.log_buf.push(' ');
                }
                Instr::LogStr { id } => {
                    // mirrors old circom-mpc-vm/src/mpc_vm.rs:863-872.
                    let idx = *id as usize;
                    if idx >= self.program.strings.len() {
                        bail!(
                            "trying to access string on pos: {idx} but len is {}",
                            self.program.strings.len()
                        );
                    }
                    self.log_buf.push_str(&self.program.strings[idx]);
                    self.log_buf.push(' ');
                }
                Instr::LogFlush { line } => {
                    // mirrors old circom-mpc-vm/src/mpc_vm.rs:873-876.
                    tracing::info!("line {line:0>4}: {}", self.log_buf);
                    self.log_buf.clear();
                }
                other => bail!("not yet implemented: {other}"),
            }
            ip += 1;
        }
        Ok(())
    }
}

/// Resolve an [`Addr`] against the integer registers.
fn resolve(frame_iregs: &[usize], addr: &Addr) -> usize {
    match addr {
        Addr::Const(c) => *c as usize,
        Addr::Affine {
            ireg,
            stride,
            offset,
        } => frame_iregs[*ireg as usize] * *stride as usize + *offset as usize,
        Addr::Dynamic(r) => frame_iregs[*r as usize],
    }
}

/// Resolve an [`Addr`], offset by `k` — used for the element-wise `*N` instructions,
/// which address consecutive slots starting at the resolved base.
fn resolve_at(frame_iregs: &[usize], addr: &Addr, k: usize) -> usize {
    resolve(frame_iregs, addr) + k
}

/// Read an operand by reference.
fn read<'v, F: PrimeField, C: VmDriver<F>>(
    frame: &'v Frame<C::VmType>,
    signals: &'v [C::VmType],
    consts: &'v [C::VmType],
    comp_offset: usize,
    src: &Src,
) -> Result<&'v C::VmType> {
    Ok(match src {
        Src::Reg(r) => &frame.regs[*r as usize],
        Src::Const(c) => &consts[*c as usize],
        Src::Var(a) => &frame.vars[resolve(&frame.iregs, a)],
        Src::Signal(a) => &signals[comp_offset + resolve(&frame.iregs, a)],
    })
}

/// Read the `k`-th element of an operand array (see [`resolve_at`]).
fn read_n<'v, F: PrimeField, C: VmDriver<F>>(
    frame: &'v Frame<C::VmType>,
    signals: &'v [C::VmType],
    consts: &'v [C::VmType],
    comp_offset: usize,
    src: &Src,
    k: usize,
) -> Result<&'v C::VmType> {
    Ok(match src {
        Src::Reg(r) => &frame.regs[*r as usize + k],
        Src::Const(c) => &consts[*c as usize + k],
        Src::Var(a) => &frame.vars[resolve_at(&frame.iregs, a, k)],
        Src::Signal(a) => &signals[comp_offset + resolve_at(&frame.iregs, a, k)],
    })
}

/// Write a value to a `Reg`/`Var`/`Signal` destination, offset by `k` (used by
/// `LoadN`/`StoreN` for element-wise writes; `k = 0` for a scalar `Mov`). This is the
/// single write path for `Dst`: `Var`/`Signal` writes are predicated by `pred` (cmux'd
/// against the current value); `Reg` writes never are (temporaries are branch-local).
#[allow(clippy::too_many_arguments)]
fn write_dst<F: PrimeField, C: VmDriver<F>>(
    driver: &mut C,
    pred: &Predication<C::VmType>,
    frame: &mut Frame<C::VmType>,
    signals: &mut [C::VmType],
    comp_offset: usize,
    dst: &Dst,
    k: usize,
    val: C::VmType,
) -> Result<()> {
    match dst {
        Dst::Reg(r) => frame.regs[*r as usize + k] = val,
        Dst::Var(a) => {
            let idx = resolve_at(&frame.iregs, a, k);
            frame.vars[idx] = predicated_merge(driver, pred, frame.vars[idx].clone(), val)?;
        }
        Dst::Signal(a) => {
            let idx = comp_offset + resolve_at(&frame.iregs, a, k);
            signals[idx] = predicated_merge(driver, pred, signals[idx].clone(), val)?;
        }
    }
    Ok(())
}

/// cmux `new` against `old` under the innermost shared-if condition, if any; otherwise
/// just `new`. Mirrors old `mpc_vm.rs:375-415` (`StoreSignals`/`StoreVars`): note the
/// new value comes first in the `cmux` call.
fn predicated_merge<F: PrimeField, C: VmDriver<F>>(
    driver: &mut C,
    pred: &Predication<C::VmType>,
    old: C::VmType,
    new: C::VmType,
) -> Result<C::VmType> {
    match pred.cond() {
        Some(cond) => driver.cmux(cond, &new, &old),
        None => Ok(new),
    }
}

/// Read an [`ISrc`] against the integer registers.
fn iread<T>(frame: &Frame<T>, src: &ISrc) -> usize {
    match src {
        ISrc::Const(c) => *c as usize,
        ISrc::Reg(r) => frame.iregs[*r as usize],
    }
}

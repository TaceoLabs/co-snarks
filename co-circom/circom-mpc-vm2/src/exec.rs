//! The execution engine.
//!
//! [`Machine`] owns the signal RAM and the constant table for one witness extension and
//! drives the register-VM dispatch loop over a [`CompiledProgram`]. This module
//! implements the straight-line, integer-unit, jump, shared-if (see [`Predication`]),
//! and function-call instruction subset; subcomponents are added by a later task
//! (instructions outside this task's subset produce a "not yet implemented" error).
//!
//! Template and function bodies share one instruction-dispatch implementation
//! (`step`): `run_component` and [`run_function`](Machine::run_function) each drive a
//! loop that calls `step` and acts on the returned `Flow`. `step` takes a `StepCtx`
//! telling it which of the two it is executing, since a few instructions are only
//! valid in one (`Return`/`CreateCmp`/`InputSub`/`OutputSub` are template-only, `Ret`
//! is function-only).
use crate::driver::{VmDriver, apply_bin};
use crate::isa::*;
use crate::program::{CompiledProgram, FunctionCode, TemplateCode, VMConfig};
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
    /// Allocate a fresh, zeroed frame sized for template `t`.
    fn for_template(t: &TemplateCode) -> Self {
        Self {
            regs: vec![T::default(); t.num_field_regs as usize],
            iregs: vec![0; t.num_int_regs as usize],
            vars: vec![T::default(); t.num_vars as usize],
        }
    }

    /// Allocate a fresh, zeroed frame sized for function `f` (`vars[0..num_params]`
    /// are overwritten with the call's arguments by [`Machine::run_function`]).
    fn for_function(f: &FunctionCode) -> Self {
        Self {
            regs: vec![T::default(); f.num_field_regs as usize],
            iregs: vec![0; f.num_int_regs as usize],
            vars: vec![T::default(); f.num_vars as usize],
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

/// What the instruction-dispatch loop ([`Machine::run_component`]/
/// [`Machine::run_function`]) should do after [`step`] returns.
enum Flow<T> {
    /// Advance to the next instruction (`ip += 1`).
    Continue,
    /// Jump to an absolute instruction index (`ip = target`, no increment).
    Jump(usize),
    /// `Return` executed (template body only): stop, no value.
    ReturnTempl,
    /// `Ret` executed and did *not* merely accumulate (function body only): stop and
    /// return these values to the caller.
    ReturnFn(Vec<T>),
}

/// Which kind of code body [`step`] is currently executing. A few instructions are
/// only valid in one of the two (see module docs); `Function` additionally carries the
/// per-activation accumulator that `Ret` under a shared predicate feeds into.
enum StepCtx<'s, T> {
    /// A template body: `Return` ends it; `Ret` is an error.
    Template,
    /// A function body: `Ret` ends it (or accumulates); `Return`/`CreateCmp`/
    /// `InputSub`/`OutputSub` are errors.
    Function {
        /// Accumulated `(condition, values)` pairs from `Ret`s executed under a shared
        /// predicate, oldest first — see [`Machine::merge_ret_acc`].
        ret_acc: &'s mut Vec<(T, Vec<T>)>,
    },
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
        let (mut frame, name) = {
            let code = &self.program.templates[comp.templ.0 as usize];
            (
                Frame::for_template(code),
                self.program.debug.names[code.symbol_id as usize].clone(),
            )
        };
        let program = self.program;
        let code = &program.templates[comp.templ.0 as usize];
        let instrs_len = code.instrs.len();
        // Fresh per component activation, matching the old per-`Component` `if_stack`;
        // threaded by reference through any function calls made from here (old
        // behavior: a shared-if context spans calls).
        let mut pred: Predication<C::VmType> = Predication::new();
        let mut kind = StepCtx::Template;
        let mut ip: usize = 0;
        loop {
            if ip >= instrs_len {
                bail!("template {name} ran off the end of its body without a Return");
            }
            let inst = &code.instrs[ip];
            match self.step(&mut frame, &mut pred, comp.offset, &name, &mut kind, inst)? {
                Flow::Continue => ip += 1,
                Flow::Jump(target) => ip = target,
                Flow::ReturnTempl => break,
                Flow::ReturnFn(_) => {
                    unreachable!("step never yields ReturnFn for a template body")
                }
            }
        }
        Ok(())
    }

    /// Execute one function activation to completion: runs until a `Ret` that
    /// (possibly after accumulating shared early returns) actually hands back values,
    /// or errors if the body falls off its end without one (see [`step`]'s `Ret`
    /// handling for the accumulation semantics; mirrors old `ReturnFun`/
    /// `ReturnSharedIfFun`, `circom-mpc-vm/src/mpc_vm.rs:752-857`).
    ///
    /// `pred` is the *caller's* predication state, threaded through by reference: a
    /// shared-if context active in the caller still applies inside the callee (old
    /// per-`Component` `if_stack` behavior — functions don't get a fresh one).
    /// `comp_offset` is the enclosing component's signal-RAM offset, for any `Signal`
    /// operands the function body reads/writes.
    pub fn run_function(
        &mut self,
        fn_id: FnId,
        args: Vec<C::VmType>,
        pred: &mut Predication<C::VmType>,
        comp_offset: usize,
    ) -> Result<Vec<C::VmType>> {
        let (mut frame, name, num_params) = {
            let code = &self.program.functions[fn_id.0 as usize];
            (
                Frame::for_function(code),
                self.program.debug.names[code.name_id as usize].clone(),
                code.num_params as usize,
            )
        };
        if args.len() != num_params {
            bail!(
                "function {name} called with {} argument(s), expected {num_params}",
                args.len()
            );
        }
        for (i, v) in args.into_iter().enumerate() {
            frame.vars[i] = v;
        }
        let program = self.program;
        let code = &program.functions[fn_id.0 as usize];
        let instrs_len = code.instrs.len();
        let mut ret_acc: Vec<(C::VmType, Vec<C::VmType>)> = Vec::new();
        let mut ip: usize = 0;
        loop {
            if ip >= instrs_len {
                // Falling off the end: a non-empty accumulator means every Ret so far
                // was under a shared predicate (old `ReturnSharedIfFun` trailer); an
                // empty one means the body never returned at all.
                if !ret_acc.is_empty() {
                    return self.merge_ret_acc(ret_acc);
                }
                bail!("function {name} ended without returning");
            }
            let inst = &code.instrs[ip];
            let mut kind = StepCtx::Function {
                ret_acc: &mut ret_acc,
            };
            match self.step(&mut frame, pred, comp_offset, &name, &mut kind, inst)? {
                Flow::Continue => ip += 1,
                Flow::Jump(target) => ip = target,
                Flow::ReturnFn(vals) => return Ok(vals),
                Flow::ReturnTempl => {
                    unreachable!("step never yields ReturnTempl for a function body")
                }
            }
        }
    }

    /// `Σ_i cond_i · val_i`, per output position, over the accumulated shared-if `Ret`
    /// entries. Mirrors old `handle_shared_fun_return`
    /// (`circom-mpc-vm/src/mpc_vm.rs:883-907`).
    fn merge_ret_acc(
        &mut self,
        ret_acc: Vec<(C::VmType, Vec<C::VmType>)>,
    ) -> Result<Vec<C::VmType>> {
        let ret_n = ret_acc.first().map(|(_, vals)| vals.len()).unwrap_or(0);
        let mut acc = vec![self.driver.public_zero(); ret_n];
        for (cond, vals) in ret_acc {
            for (slot, v) in acc.iter_mut().zip(vals.iter()) {
                let contribution = self.driver.mul(&cond, v)?;
                *slot = self.driver.add(slot, &contribution)?;
            }
        }
        Ok(acc)
    }

    /// Execute one instruction, shared between template and function bodies (see
    /// module docs). `name` is the enclosing template/function's name, used in error
    /// messages. Returns the [`Flow`] the caller's dispatch loop should act on.
    fn step(
        &mut self,
        frame: &mut Frame<C::VmType>,
        pred: &mut Predication<C::VmType>,
        comp_offset: usize,
        name: &str,
        kind: &mut StepCtx<C::VmType>,
        inst: &Instr,
    ) -> Result<Flow<C::VmType>> {
        Ok(match inst {
            Instr::Bin { op, dst, a, b } => {
                let r = {
                    let a = read::<F, C>(frame, &self.signals, &self.consts, comp_offset, a)?;
                    let b = read::<F, C>(frame, &self.signals, &self.consts, comp_offset, b)?;
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
                Flow::Continue
            }
            Instr::Neg { dst, a } => {
                let r = {
                    let a = read::<F, C>(frame, &self.signals, &self.consts, comp_offset, a)?;
                    self.driver.neg(a)?
                };
                frame.regs[*dst as usize] = r;
                Flow::Continue
            }
            Instr::EqN { dst, a, b, n } => {
                // Per-element eq, folded with bool_and, initial accumulator public_one —
                // mirrors old circom-mpc-vm/src/mpc_vm.rs:663-679.
                let mut result = self.driver.public_one();
                for k in 0..*n as usize {
                    let av = read_n::<F, C>(frame, &self.signals, &self.consts, comp_offset, a, k)?
                        .clone();
                    let bv = read_n::<F, C>(frame, &self.signals, &self.consts, comp_offset, b, k)?
                        .clone();
                    let cmp = self.driver.eq(&av, &bv)?;
                    result = self.driver.bool_and(&cmp, &result)?;
                }
                frame.regs[*dst as usize] = result;
                Flow::Continue
            }
            Instr::Mov { dst, src } => {
                let v = read::<F, C>(frame, &self.signals, &self.consts, comp_offset, src)?.clone();
                write_dst::<F, C>(
                    self.driver,
                    &*pred,
                    frame,
                    &mut self.signals,
                    comp_offset,
                    dst,
                    0,
                    v,
                )?;
                Flow::Continue
            }
            Instr::LoadN { dst, src, n } => {
                // Consecutive reads from the source address; scatter into regs[dst..dst+n].
                for k in 0..*n as usize {
                    let v =
                        read_n::<F, C>(frame, &self.signals, &self.consts, comp_offset, src, k)?
                            .clone();
                    frame.regs[*dst as usize + k] = v;
                }
                Flow::Continue
            }
            Instr::StoreN { dst, src, n } => {
                // Consecutive predicated writes.
                for k in 0..*n as usize {
                    let v = frame.regs[*src as usize + k].clone();
                    write_dst::<F, C>(
                        self.driver,
                        &*pred,
                        frame,
                        &mut self.signals,
                        comp_offset,
                        dst,
                        k,
                        v,
                    )?;
                }
                Flow::Continue
            }
            Instr::BinN { op, dst, a, b, n } => {
                // Gather operands, one vectorized driver call, scatter results.
                let n = *n as usize;
                let mut av = Vec::with_capacity(n);
                let mut bv = Vec::with_capacity(n);
                for k in 0..n {
                    av.push(
                        read_n::<F, C>(frame, &self.signals, &self.consts, comp_offset, a, k)?
                            .clone(),
                    );
                    bv.push(
                        read_n::<F, C>(frame, &self.signals, &self.consts, comp_offset, b, k)?
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
                Flow::Continue
            }
            Instr::ISet { dst, val } => {
                frame.iregs[*dst as usize] = *val as usize;
                Flow::Continue
            }
            Instr::IAdd { dst, a, b } => {
                frame.iregs[*dst as usize] = iread(frame, a) + iread(frame, b);
                Flow::Continue
            }
            Instr::IMul { dst, a, b } => {
                frame.iregs[*dst as usize] = iread(frame, a) * iread(frame, b);
                Flow::Continue
            }
            Instr::ToIndex { dst, src } => {
                let v = read::<F, C>(frame, &self.signals, &self.consts, comp_offset, src)?.clone();
                frame.iregs[*dst as usize] = self.driver.to_index(&v)?;
                Flow::Continue
            }
            Instr::Jmp { target } => Flow::Jump(*target as usize),
            Instr::JmpIfZero { cond, target } => {
                let c =
                    read::<F, C>(frame, &self.signals, &self.consts, comp_offset, cond)?.clone();
                if self.driver.is_zero(&c, false)? {
                    Flow::Jump(*target as usize)
                } else {
                    Flow::Continue
                }
            }
            Instr::SharedIf { cond, else_target } => {
                // mirrors old mpc_vm.rs:562-576 (`MpcOpCode::If`).
                let c =
                    read::<F, C>(frame, &self.signals, &self.consts, comp_offset, cond)?.clone();
                if self.driver.is_shared(&c)? {
                    pred.push_shared(self.driver, c)?;
                    Flow::Continue
                } else {
                    pred.push_public();
                    if self.driver.is_zero(&c, false)? {
                        Flow::Jump(*else_target as usize)
                    } else {
                        Flow::Continue
                    }
                }
            }
            Instr::SharedElse { end_target } => {
                // mirrors old mpc_vm.rs:577-592 (`MpcOpCode::EndTruthyBranch`): a public
                // level jumps past the else branch straight to `SharedEnd` (still
                // executing the pop); a shared level falls into the else branch with its
                // condition toggled.
                if pred.top_is_public() {
                    Flow::Jump(*end_target as usize)
                } else {
                    pred.toggle(self.driver)?;
                    Flow::Continue
                }
            }
            Instr::SharedEnd => {
                pred.pop(); // mirrors old mpc_vm.rs:593-598 (`EndFalsyBranch`).
                Flow::Continue
            }
            Instr::Return => match kind {
                StepCtx::Template => Flow::ReturnTempl,
                StepCtx::Function { .. } => {
                    bail!("Return used inside function {name} (expected Ret)")
                }
            },
            Instr::Ret { src, n } => {
                let ret_acc = match kind {
                    StepCtx::Function { ret_acc } => &mut **ret_acc,
                    StepCtx::Template => {
                        bail!("Ret used inside template {name} (expected Return)")
                    }
                };
                let vals: Vec<C::VmType> =
                    (0..*n as usize).map(|k| read_ret(frame, src, k)).collect();
                // Exact port of old `ReturnFun` (`circom-mpc-vm/src/mpc_vm.rs:752-847`).
                if pred.is_shared() {
                    // This Ret may or may not actually fire (data-dependent): record its
                    // condition (minus every earlier accumulated Ret's condition, so at
                    // most one entry ever contributes) and keep executing.
                    let mut this_cond =
                        pred.cond().expect("is_shared implies cond is Some").clone();
                    for (c, _) in ret_acc.iter() {
                        let notc = self.driver.bool_not(c)?;
                        this_cond = self.driver.bool_and(&this_cond, &notc)?;
                    }
                    ret_acc.push((this_cond, vals));
                    Flow::Continue
                } else if !ret_acc.is_empty() {
                    // This Ret is unconditional (we're no longer under any shared level),
                    // but earlier shared Rets might have already "returned" — this is the
                    // final entry (condition = AND of all earlier negations) and we merge
                    // now.
                    let mut this_cond = self.driver.public_one();
                    for (c, _) in ret_acc.iter() {
                        let notc = self.driver.bool_not(c)?;
                        this_cond = self.driver.bool_and(&this_cond, &notc)?;
                    }
                    ret_acc.push((this_cond, vals));
                    let acc = std::mem::take(ret_acc);
                    Flow::ReturnFn(self.merge_ret_acc(acc)?)
                } else {
                    // Fast path: no shared early returns seen at all.
                    Flow::ReturnFn(vals)
                }
            }
            Instr::CallFn {
                fn_id,
                args_start,
                args_n,
                ret,
                ret_n,
            } => {
                let args: Vec<C::VmType> = frame.regs
                    [*args_start as usize..*args_start as usize + *args_n as usize]
                    .to_vec();
                let result = self.run_function(*fn_id, args, pred, comp_offset)?;
                if result.len() != *ret_n as usize {
                    let fname = &self.program.debug.names
                        [self.program.functions[fn_id.0 as usize].name_id as usize];
                    bail!(
                        "function {fname} returned {} value(s), expected {ret_n}",
                        result.len()
                    );
                }
                for (k, v) in result.into_iter().enumerate() {
                    frame.regs[*ret as usize + k] = v;
                }
                Flow::Continue
            }
            Instr::CreateCmp { .. } | Instr::InputSub { .. } | Instr::OutputSub { .. } => {
                match kind {
                    StepCtx::Function { .. } => {
                        bail!("{inst} is template-only, cannot appear inside function {name}")
                    }
                    StepCtx::Template => bail!("not yet implemented: {inst}"),
                }
            }
            Instr::Assert { cond, line } => {
                let c =
                    read::<F, C>(frame, &self.signals, &self.consts, comp_offset, cond)?.clone();
                if self.driver.is_zero(&c, true)? {
                    let ctx_word = match kind {
                        StepCtx::Template => "component",
                        StepCtx::Function { .. } => "function",
                    };
                    bail!("Assertion failed during execution on line {line} in {ctx_word} {name}");
                }
                Flow::Continue
            }
            Instr::Log { src } => {
                // mirrors old circom-mpc-vm/src/mpc_vm.rs:858-862.
                let v = read::<F, C>(frame, &self.signals, &self.consts, comp_offset, src)?.clone();
                let log = self.driver.log(&v, self.config.allow_leaky_logs)?;
                self.log_buf.push_str(&log);
                self.log_buf.push(' ');
                Flow::Continue
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
                Flow::Continue
            }
            Instr::LogFlush { line } => {
                // mirrors old circom-mpc-vm/src/mpc_vm.rs:873-876.
                tracing::info!("line {line:0>4}: {}", self.log_buf);
                self.log_buf.clear();
                Flow::Continue
            }
        })
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

/// Read the `k`-th value of a `Ret` source (regs or vars; see [`RetSrc`]), cloned.
fn read_ret<T: Clone>(frame: &Frame<T>, src: &RetSrc, k: usize) -> T {
    match src {
        RetSrc::Reg(r) => frame.regs[*r as usize + k].clone(),
        RetSrc::Var(a) => frame.vars[resolve_at(&frame.iregs, a, k)].clone(),
    }
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

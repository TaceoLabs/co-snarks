//! The execution engine.
//!
//! [`Machine`] owns the signal RAM and the constant table for one witness extension and
//! drives the register-VM dispatch loop over a [`CompiledProgram`]. This module
//! implements the straight-line, integer-unit, jump, shared-if (see [`Predication`]),
//! function-call, and subcomponent (`CreateCmp`/`InputSub`/`OutputSub`) instruction
//! subsets — the full template/function instruction set.
//!
//! Template and function bodies share one instruction-dispatch implementation
//! (`step`): `run_component` and [`run_function`](Machine::run_function) each drive a
//! loop that calls `step` and acts on the returned `Flow`. `step` takes a `StepCtx`
//! telling it which of the two it is executing, since a few instructions are only
//! valid in one (`Return`/`CreateCmp`/`InputSub`/`OutputSub` are template-only, `Ret`
//! is function-only). Subcomponents are owned by the parent's `ComponentInst` (not by
//! `Machine`), so `step` additionally takes an `Option<&mut ComponentInst>`: `Some` in
//! a template body, `None` in a function body (which can never reference
//! subcomponents — those three instructions bail immediately there). This lets `step`
//! recurse into `run_component` for a freshly-created or newly-completed subcomponent
//! without fighting the borrow checker, since the subcomponent is reachable through a
//! parameter rather than through `self`.
use crate::accel::{AccelBindings, MpcAccelerator};
use crate::driver::{VmDriver, apply_bin};
use crate::isa::*;
use crate::program::{CompiledProgram, FunctionCode, TemplateCode, VMConfig};
use ark_ff::PrimeField;
use eyre::{Result, bail};
use std::collections::HashSet;

/// Per-activation register frame.
pub struct Frame<T> {
    /// Field-register file (expression temporaries).
    pub regs: Vec<T>,
    /// Integer-register file (loop/addressing indices).
    pub iregs: Vec<usize>,
    /// Local variable slots.
    pub vars: Vec<T>,
}

/// A `Var`/`Signal` slot whose speculative value must be merged before leaving the
/// current straight-line predicated region.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum WriteLoc {
    Var(usize),
    Signal(usize),
}

/// Lazily records the value preceding the first write to every destination in a
/// straight-line shared branch region. Writes update the live frame/signal RAM
/// immediately, so read-after-write observes the branch-local value. At a control or
/// side-effect boundary all dirty destinations are merged in one `cmux_many` call.
struct PendingWrites<T> {
    entries: Vec<(WriteLoc, T)>,
    dirty: HashSet<WriteLoc>,
}

impl<T: Clone> PendingWrites<T> {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            dirty: HashSet::new(),
        }
    }

    fn write_var(&mut self, vars: &mut [T], idx: usize, value: T) {
        let loc = WriteLoc::Var(idx);
        if self.dirty.insert(loc) {
            self.entries.push((loc, vars[idx].clone()));
        }
        vars[idx] = value;
    }

    fn write_signal(&mut self, signals: &mut [T], idx: usize, value: T) {
        let loc = WriteLoc::Signal(idx);
        if self.dirty.insert(loc) {
            self.entries.push((loc, signals[idx].clone()));
        }
        signals[idx] = value;
    }

    fn flush<F, C>(
        &mut self,
        driver: &mut C,
        pred: &Predication<T>,
        frame: &mut Frame<T>,
        signals: &mut [T],
    ) -> Result<()>
    where
        F: PrimeField,
        C: VmDriver<F, VmType = T>,
    {
        if self.entries.is_empty() {
            return Ok(());
        }
        let cond = pred
            .cond()
            .expect("pending writes only exist under a shared predicate");
        let entries = std::mem::take(&mut self.entries);
        self.dirty.clear();

        let mut locations = Vec::with_capacity(entries.len());
        let mut old = Vec::with_capacity(entries.len());
        let mut new = Vec::with_capacity(entries.len());
        for (loc, previous) in entries {
            let current = match loc {
                WriteLoc::Var(idx) => frame.vars[idx].clone(),
                WriteLoc::Signal(idx) => signals[idx].clone(),
            };
            locations.push(loc);
            old.push(previous);
            new.push(current);
        }

        let merged = driver.cmux_many(cond, &new, &old)?;
        for (loc, value) in locations.into_iter().zip(merged) {
            match loc {
                WriteLoc::Var(idx) => frame.vars[idx] = value,
                WriteLoc::Signal(idx) => signals[idx] = value,
            }
        }
        Ok(())
    }
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
    /// Number of input values received so far (drives run-on-last-input: the
    /// subcomponent is run once this reaches its template's `input_signals`).
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
    /// The bound accelerator registry for this run, if any (see
    /// [`Machine::new_with_accelerator`]): the registry itself (to dispatch through)
    /// plus its [`AccelBindings`] against `program` (computed once, at construction).
    accel: Option<(&'a MpcAccelerator<F, C>, AccelBindings)>,
}

impl<'a, F: PrimeField, C: VmDriver<F>> Machine<'a, F, C> {
    /// Allocate signal RAM, inject constants, place the constant 1 at signal 0. No
    /// accelerator is bound — every component/function runs its own body (see
    /// [`Machine::new_with_accelerator`] to bind one).
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
            accel: None,
        })
    }

    /// Same as [`Machine::new`], but also binds `accelerator`'s registrations against
    /// `program` (see [`MpcAccelerator::bind`](crate::accel::MpcAccelerator::bind)):
    /// [`Machine::run_component`] and the `CallFn` instruction dispatch (see [`step`])
    /// consult the resulting bindings before running a component/function body.
    pub fn new_with_accelerator(
        program: &'a CompiledProgram<F>,
        driver: &'a mut C,
        config: VMConfig,
        accelerator: &'a MpcAccelerator<F, C>,
    ) -> Result<Self> {
        let mut machine = Self::new(program, driver, config)?;
        let bindings = accelerator.bind(program);
        machine.accel = Some((accelerator, bindings));
        Ok(machine)
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

    /// Execute one template activation to completion (until `Return`), unless an
    /// accelerator is bound for its template (see [`Machine::new_with_accelerator`]):
    /// in that case its body is skipped entirely, and the accelerator's outputs and
    /// intermediates are written straight into signal RAM instead (mirrors old
    /// `mpc_vm.rs:326-354`).
    fn run_component(&mut self, comp: &mut ComponentInst) -> Result<()> {
        let program = self.program;
        let code = &program.templates[comp.templ.0 as usize];
        let name: &str = &program.debug.names[code.symbol_id as usize];

        // `self.accel` is `Option<(&'a MpcAccelerator<F, C>, AccelBindings)>`: both the
        // registry reference and the `usize` index are `Copy`, so this extracts an
        // owned tuple and drops the borrow of `self.accel` immediately, leaving
        // `self.driver`/`self.signals` free to borrow mutably below.
        let dispatch = self.accel.as_ref().and_then(|(accel, bindings)| {
            bindings.component_accel(comp.templ).map(|i| (*accel, i))
        });
        if let Some((accelerator, accel_idx)) = dispatch {
            let output_signals = code.output_signals as usize;
            let input_signals = code.input_signals as usize;
            let input_start = comp.offset + output_signals;
            let intermediate_start = input_start + input_signals;
            let inputs = self.signals[input_start..intermediate_start].to_vec();
            let result =
                accelerator.run_component(accel_idx, self.driver, &inputs, output_signals)?;
            if result.output.len() != output_signals {
                bail!(
                    "accelerator for component {name} returned {} output(s), expected {output_signals}",
                    result.output.len()
                );
            }
            let intermediate_signals = code.intermediate_signals as usize;
            if result.intermediate.len() > intermediate_signals {
                bail!(
                    "accelerator for component {name} returned {} intermediate signal(s), but the template has only {intermediate_signals} slot(s)",
                    result.intermediate.len()
                );
            }
            self.signals[comp.offset..comp.offset + output_signals]
                .clone_from_slice(&result.output);
            let intermediate_end = intermediate_start + result.intermediate.len();
            self.signals[intermediate_start..intermediate_end]
                .clone_from_slice(&result.intermediate);
            return Ok(());
        }

        let mut frame = Frame::for_template(code);
        let instrs_len = code.instrs.len();
        // Fresh per component activation, matching the old per-`Component` `if_stack`;
        // threaded by reference through any function calls made from here (old
        // behavior: a shared-if context spans calls).
        let mut pred: Predication<C::VmType> = Predication::new();
        let mut pending = PendingWrites::new();
        let mut kind = StepCtx::Template;
        let mut ip: usize = 0;
        loop {
            if ip >= instrs_len {
                bail!("template {name} ran off the end of its body without a Return");
            }
            let inst = &code.instrs[ip];
            let offset = comp.offset;
            match self.step(
                &mut frame,
                &mut pred,
                &mut pending,
                offset,
                name,
                &mut kind,
                inst,
                Some(&mut *comp),
            )? {
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
    ///
    /// `ret_n` is the *callsite's* arity (the `CallFn`'s `ret_n`), not the callee's own
    /// idea of how many values it returns: old-VM parity (`circom-mpc-vm/src/mpc_vm.rs:788-838`)
    /// has the callsite determine the arity, resizing/zero-padding a callee that
    /// returns fewer values and truncating one that returns more — see
    /// [`Machine::resize_ret`], applied at every return boundary below.
    pub fn run_function(
        &mut self,
        fn_id: FnId,
        args: Vec<C::VmType>,
        pred: &mut Predication<C::VmType>,
        comp_offset: usize,
        ret_n: usize,
    ) -> Result<Vec<C::VmType>> {
        let program = self.program;
        let code = &program.functions[fn_id.0 as usize];
        let name: &str = &program.debug.names[code.name_id as usize];
        let num_params = code.num_params as usize;
        let mut frame = Frame::for_function(code);
        if args.len() != num_params {
            bail!(
                "function {name} called with {} argument(s), expected {num_params}",
                args.len()
            );
        }
        for (i, v) in args.into_iter().enumerate() {
            frame.vars[i] = v;
        }
        let instrs_len = code.instrs.len();
        let mut ret_acc: Vec<(C::VmType, Vec<C::VmType>)> = Vec::new();
        let mut pending = PendingWrites::new();
        let mut ip: usize = 0;
        loop {
            if ip >= instrs_len {
                // Falling off the end: a non-empty accumulator means every Ret so far
                // was under a shared predicate (old `ReturnSharedIfFun` trailer); an
                // empty one means the body never returned at all.
                pending.flush::<F, C>(self.driver, pred, &mut frame, &mut self.signals)?;
                if !ret_acc.is_empty() {
                    let vals = self.merge_ret_acc(ret_acc)?;
                    return Ok(self.resize_ret(vals, ret_n));
                }
                bail!("function {name} ended without returning");
            }
            let inst = &code.instrs[ip];
            let mut kind = StepCtx::Function {
                ret_acc: &mut ret_acc,
            };
            match self.step(
                &mut frame,
                pred,
                &mut pending,
                comp_offset,
                name,
                &mut kind,
                inst,
                None,
            )? {
                Flow::Continue => ip += 1,
                Flow::Jump(target) => ip = target,
                Flow::ReturnFn(vals) => return Ok(self.resize_ret(vals, ret_n)),
                Flow::ReturnTempl => {
                    unreachable!("step never yields ReturnTempl for a function body")
                }
            }
        }
    }

    /// `Σ_i cond_i · val_i`, per output position, over the accumulated shared-if `Ret`
    /// entries. Entries may differ in length (old `ReturnFun`'s resize-on-return lets
    /// different shared branches return different arities, `circom-mpc-vm/src/mpc_vm.rs:791-795`):
    /// the merged length is the longest entry, and any entry missing a position simply
    /// contributes zero there. Mirrors old `handle_shared_fun_return`
    /// (`circom-mpc-vm/src/mpc_vm.rs:883-907`).
    fn merge_ret_acc(
        &mut self,
        ret_acc: Vec<(C::VmType, Vec<C::VmType>)>,
    ) -> Result<Vec<C::VmType>> {
        let ret_n = ret_acc
            .iter()
            .map(|(_, vals)| vals.len())
            .max()
            .unwrap_or(0);
        let mut acc = vec![self.driver.public_zero(); ret_n];
        for (cond, vals) in ret_acc {
            for (slot, v) in acc.iter_mut().zip(vals.iter()) {
                let contribution = self.driver.mul(&cond, v)?;
                *slot = self.driver.add(slot, &contribution)?;
            }
            // Entries shorter than `ret_n` simply stop contributing past their own
            // length — the `zip` above already skips them, so nothing else to do.
        }
        Ok(acc)
    }

    /// Resize `vals` to exactly `ret_n` elements: pad with `public_zero()` if shorter,
    /// truncate if longer. This is the callsite-arity boundary applied at every
    /// [`Machine::run_function`] return path (old-VM parity, see that method's docs).
    fn resize_ret(&mut self, mut vals: Vec<C::VmType>, ret_n: usize) -> Vec<C::VmType> {
        if vals.len() < ret_n {
            vals.resize_with(ret_n, || self.driver.public_zero());
        } else {
            vals.truncate(ret_n);
        }
        vals
    }

    /// Execute one instruction, shared between template and function bodies (see
    /// module docs). `name` is the enclosing template/function's name, used in error
    /// messages. `comp` is the CURRENT component being executed (holding its own
    /// subcomponent tree) — `Some` when called from `run_component` (template body),
    /// `None` when called from `run_function` (a function body can never touch
    /// subcomponents). Returns the [`Flow`] the caller's dispatch loop should act on.
    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        frame: &mut Frame<C::VmType>,
        pred: &mut Predication<C::VmType>,
        pending: &mut PendingWrites<C::VmType>,
        comp_offset: usize,
        name: &str,
        kind: &mut StepCtx<C::VmType>,
        inst: &Instr,
        comp: Option<&mut ComponentInst>,
    ) -> Result<Flow<C::VmType>> {
        if is_write_barrier(inst) {
            pending.flush::<F, C>(self.driver, pred, frame, &mut self.signals)?;
        }
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
                    let av = read_n::<F, C>(frame, &self.signals, &self.consts, comp_offset, a, k)?;
                    let bv = read_n::<F, C>(frame, &self.signals, &self.consts, comp_offset, b, k)?;
                    let cmp = self.driver.eq(av, bv)?;
                    result = self.driver.bool_and(&cmp, &result)?;
                }
                frame.regs[*dst as usize] = result;
                Flow::Continue
            }
            Instr::Mov { dst, src } => {
                let v = read::<F, C>(frame, &self.signals, &self.consts, comp_offset, src)?.clone();
                write_dst::<F, C>(
                    &*pred,
                    pending,
                    frame,
                    &mut self.signals,
                    comp_offset,
                    dst,
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
                // Consecutive predicated writes, batched through one `cmux_many` call
                // (see `write_dst_n`) instead of `n` scalar `cmux`s.
                let vals: Vec<_> = (0..*n as usize)
                    .map(|k| frame.regs[*src as usize + k].clone())
                    .collect();
                write_dst_n::<F, C>(
                    &*pred,
                    pending,
                    frame,
                    &mut self.signals,
                    comp_offset,
                    dst,
                    vals,
                )?;
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
            Instr::SharedIf { cond, else_target } | Instr::SharedIfBit { cond, else_target } => {
                // mirrors old mpc_vm.rs:562-576 (`MpcOpCode::If`).
                let c =
                    read::<F, C>(frame, &self.signals, &self.consts, comp_offset, cond)?.clone();
                if self.driver.is_shared(&c)? {
                    // Circom conditions use zero/non-zero truthiness, while protocol cmux
                    // and boolean-composition primitives require a bit. Comparisons and
                    // boolean operators already produce one, and `SharedIfBit` preserves
                    // that fact from codegen so Rep3 can skip an expensive redundant neq.
                    let c = if matches!(inst, Instr::SharedIfBit { .. }) {
                        c
                    } else {
                        let zero = self.driver.public_zero();
                        self.driver.neq(&c, &zero)?
                    };
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
                // Same borrow-shedding trick as `run_component`'s accelerator dispatch
                // (see its docs): extract a `Copy` `(accelerator, accel_idx)` pair before
                // touching `self.driver`.
                let dispatch = self.accel.as_ref().and_then(|(accel, bindings)| {
                    bindings.function_accel(*fn_id).map(|i| (*accel, i))
                });
                // The callsite's `ret_n` is the arity contract in both branches: an
                // accelerated call's results are padded/truncated exactly like a normal
                // `run_function` return (old-VM parity, see that method's docs) — this
                // is also what fixes old-VM's single-value-only accelerator limitation,
                // since multi-value returns now go through the same resize path.
                let result = if let Some((accelerator, accel_idx)) = dispatch {
                    let vals = accelerator.run_function(accel_idx, self.driver, &args)?;
                    self.resize_ret(vals, *ret_n as usize)
                } else {
                    self.run_function(*fn_id, args, pred, comp_offset, *ret_n as usize)?
                };
                for (k, v) in result.into_iter().enumerate() {
                    frame.regs[*ret as usize + k] = v;
                }
                Flow::Continue
            }
            Instr::CreateCmp {
                templ,
                count,
                base,
                jump,
            } => match kind {
                StepCtx::Function { .. } => {
                    bail!("{inst} is template-only, cannot appear inside function {name}")
                }
                StepCtx::Template => {
                    // mirrors old mpc_vm.rs:462-486 (`MpcOpCode::CreateCmp`).
                    let comp = comp.expect("StepCtx::Template always supplies a ComponentInst");
                    let program = self.program;
                    let tcode = &program.templates[templ.0 as usize];
                    let input_signals = tcode.input_signals;
                    let sub_capacity = tcode.sub_components as usize;
                    for i in 0..*count as usize {
                        let offset = comp.offset + *base as usize + i * *jump as usize;
                        let mut new_sub = ComponentInst {
                            templ: *templ,
                            offset,
                            provided_inputs: 0,
                            sub: Vec::with_capacity(sub_capacity),
                        };
                        // mirrors old mpc_vm.rs:480-485: a zero-input subcomponent has
                        // nothing left to wait for, so it runs immediately at creation.
                        if input_signals == 0 {
                            self.run_component(&mut new_sub)?;
                        }
                        comp.sub.push(new_sub);
                    }
                    Flow::Continue
                }
            },
            Instr::InputSub {
                cmp,
                addr,
                mapped,
                src,
                n,
            } => match kind {
                StepCtx::Function { .. } => {
                    bail!("{inst} is template-only, cannot appear inside function {name}")
                }
                StepCtx::Template => {
                    // mirrors old mpc_vm.rs:500-503: was an `assert!`, now a proper error.
                    if pred.is_shared() {
                        bail!("cannot provide subcomponent inputs inside a shared if in {name}");
                    }
                    let comp = comp.expect("StepCtx::Template always supplies a ComponentInst");
                    let idx = iread(frame, cmp);
                    if idx >= comp.sub.len() {
                        bail!(
                            "InputSub: subcomponent index {idx} out of range \
                             ({} subcomponent(s)) in {name}",
                            comp.sub.len()
                        );
                    }
                    // mirrors old mpc_vm.rs:499-552 (minus the TACEO_PRECOMPUTATION
                    // branch, out of scope for this task).
                    let program = self.program;
                    let sub_code = &program.templates[comp.sub[idx].templ.0 as usize];
                    let mut a = resolve(&frame.iregs, addr);
                    if let Some(m) = mapped {
                        a += sub_code.mappings[*m as usize] as usize;
                    }
                    let input_signals = sub_code.input_signals;
                    let sub_offset = comp.sub[idx].offset;
                    let n = *n as usize;
                    for k in 0..n {
                        self.signals[sub_offset + a + k] = frame.regs[*src as usize + k].clone();
                    }
                    comp.sub[idx].provided_inputs += n as u32;
                    if comp.sub[idx].provided_inputs == input_signals {
                        self.run_component(&mut comp.sub[idx])?;
                    }
                    Flow::Continue
                }
            },
            Instr::OutputSub {
                cmp,
                addr,
                mapped,
                dst,
                n,
            } => match kind {
                StepCtx::Function { .. } => {
                    bail!("{inst} is template-only, cannot appear inside function {name}")
                }
                StepCtx::Template => {
                    // mirrors old mpc_vm.rs:487-498 (`MpcOpCode::OutputSubComp`) — not
                    // gated on predication, matching the old behavior.
                    let comp = comp.expect("StepCtx::Template always supplies a ComponentInst");
                    let idx = iread(frame, cmp);
                    if idx >= comp.sub.len() {
                        bail!(
                            "OutputSub: subcomponent index {idx} out of range \
                             ({} subcomponent(s)) in {name}",
                            comp.sub.len()
                        );
                    }
                    let program = self.program;
                    let sub_code = &program.templates[comp.sub[idx].templ.0 as usize];
                    let mut a = resolve(&frame.iregs, addr);
                    if let Some(m) = mapped {
                        a += sub_code.mappings[*m as usize] as usize;
                    }
                    let sub_offset = comp.sub[idx].offset;
                    let n = *n as usize;
                    for k in 0..n {
                        frame.regs[*dst as usize + k] = self.signals[sub_offset + a + k].clone();
                    }
                    Flow::Continue
                }
            },
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

/// Instructions that can change the active predicate, transfer execution to another
/// activation, or externally observe state. Speculative branch writes must be merged
/// before any of these boundaries. Arithmetic, loads, stores, and integer-address
/// calculations deliberately remain barrier-free so an entire straight-line region
/// shares one batched merge.
fn is_write_barrier(inst: &Instr) -> bool {
    matches!(
        inst,
        Instr::Jmp { .. }
            | Instr::JmpIfZero { .. }
            | Instr::SharedIf { .. }
            | Instr::SharedIfBit { .. }
            | Instr::SharedElse { .. }
            | Instr::SharedEnd
            | Instr::Return
            | Instr::Ret { .. }
            | Instr::CallFn { .. }
            | Instr::CreateCmp { .. }
            | Instr::InputSub { .. }
            | Instr::OutputSub { .. }
            | Instr::Assert { .. }
            | Instr::Log { .. }
            | Instr::LogStr { .. }
            | Instr::LogFlush { .. }
    )
}

/// Write a value to a scalar `Reg`/`Var`/`Signal` destination (used by `Mov`; see
/// `write_dst_n` for the element-wise `LoadN`/`StoreN` counterpart). Together the two
/// are the single write path for `Dst`: shared-predicated `Var`/`Signal` writes are
/// recorded in `pending` and merged at the next barrier; `Reg` writes never are
/// predicated because temporaries are branch-local.
fn write_dst<F: PrimeField, C: VmDriver<F>>(
    pred: &Predication<C::VmType>,
    pending: &mut PendingWrites<C::VmType>,
    frame: &mut Frame<C::VmType>,
    signals: &mut [C::VmType],
    comp_offset: usize,
    dst: &Dst,
    val: C::VmType,
) -> Result<()> {
    match dst {
        Dst::Reg(r) => frame.regs[*r as usize] = val,
        Dst::Var(a) => {
            let idx = resolve(&frame.iregs, a);
            if pred.is_shared() {
                pending.write_var(&mut frame.vars, idx, val);
            } else {
                frame.vars[idx] = val;
            }
        }
        Dst::Signal(a) => {
            let idx = comp_offset + resolve(&frame.iregs, a);
            if pred.is_shared() {
                pending.write_signal(signals, idx, val);
            } else {
                signals[idx] = val;
            }
        }
    }
    Ok(())
}

/// Write `n` consecutive values to a `Dst`, starting at its base address (used by
/// `StoreN`). Shared `Var`/`Signal` writes join the same pending batch as scalar `Mov`s;
/// unpredicated writes update their destination directly. `Reg` writes are always
/// immediate because temporaries are branch-local.
fn write_dst_n<F: PrimeField, C: VmDriver<F>>(
    pred: &Predication<C::VmType>,
    pending: &mut PendingWrites<C::VmType>,
    frame: &mut Frame<C::VmType>,
    signals: &mut [C::VmType],
    comp_offset: usize,
    dst: &Dst,
    vals: Vec<C::VmType>,
) -> Result<()> {
    match dst {
        Dst::Reg(r) => {
            for (k, v) in vals.into_iter().enumerate() {
                frame.regs[*r as usize + k] = v;
            }
        }
        Dst::Var(a) => {
            for (k, value) in vals.into_iter().enumerate() {
                let idx = resolve_at(&frame.iregs, a, k);
                if pred.is_shared() {
                    pending.write_var(&mut frame.vars, idx, value);
                } else {
                    frame.vars[idx] = value;
                }
            }
        }
        Dst::Signal(a) => {
            for (k, value) in vals.into_iter().enumerate() {
                let idx = comp_offset + resolve_at(&frame.iregs, a, k);
                if pred.is_shared() {
                    pending.write_signal(signals, idx, value);
                } else {
                    signals[idx] = value;
                }
            }
        }
    }
    Ok(())
}

/// Read an [`ISrc`] against the integer registers.
fn iread<T>(frame: &Frame<T>, src: &ISrc) -> usize {
    match src {
        ISrc::Const(c) => *c as usize,
        ISrc::Reg(r) => frame.iregs[*r as usize],
    }
}

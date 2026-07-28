# circom-mpc-compiler2

Compiles `.circom` circuits into bytecode for the register-based [`circom-mpc-vm2`](../circom-mpc-vm2) MPC-VM.

This crate is the successor of [`circom-mpc-compiler`](../circom-mpc-compiler). The two crates live side by side: `circom-mpc-compiler` is untouched and remains the production path, while `circom-mpc-compiler2` is the target of ongoing migration work. Where the old crate lowers to `circom-mpc-vm`'s stack-based bytecode, this crate targets `circom-mpc-vm2`'s three-address instruction set and produces a `CompiledProgram` that the new VM executes directly.

Like the circom compiler it wraps, this crate is licensed **GPL-3.0**. Downstream code that only depends on `circom-mpc-vm2` (i.e. runs already-compiled programs) is unaffected.

## Pipeline overview

```
.circom file
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│ Frontend (src/frontend.rs)                                  │
│   circom parser → type checker → constraint generation      │
│   produces the circom `Circuit` IR + output-signal mapping  │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│ Codegen (src/codegen/)                                      │
│   phase 1: template/function id assignment, constant table  │
│   phase 2: per-body lowering of IR buckets to `Instr`s      │
│     - expression lowering        (expr.rs)                  │
│     - statement lowering         (stmt.rs)                  │
│     - symbolic index folding     (index.rs)                 │
│     - variable bindings          (env.rs)                   │
│     - register allocation        (regalloc.rs)              │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│ Post-lowering passes (src/codegen/passes/)                  │
│   per body, to a fixed point:                               │
│     CFG validation → SCCP constant folding → unreachable-   │
│     code removal → jump cleanup → copy propagation →        │
│     var-load forwarding → dead-store elimination →          │
│     common-subexpression elimination → dead-code            │
│     elimination                                             │
│   then once: interactive-operation batching                 │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
CompiledProgram (circom_mpc_vm2::program) — serializable artifact
```

The public entry points are `CoCircomCompiler::parse` (full pipeline) and `CoCircomCompiler::get_public_inputs` (frontend only). The compiler is generic over a pairing curve; `bn254` and `bls12-381` are supported.

## Frontend (`src/frontend.rs`)

The "front half" mirrors the old `circom-mpc-compiler` almost verbatim: it runs the circom compiler's own parser, type checker, and constraint-generation crates (via the TACEO fork of circom). The output is:

- a circom `Circuit`: one IR "bucket" tree (`LoadBucket`, `StoreBucket`, `ComputeBucket`, `LoopBucket`, `BranchBucket`, ...) per *monomorphized* template and per function, plus the constant/string tables and signal-layout metadata from the `c_producer`, and
- an `OutputMapping`: output signal name → `(offset, size)` in the witness layout.

Everything below this point is new relative to the old crate.

## Codegen (`src/codegen/`)

Lowering is two-phase (`codegen::compile`):

1. **Id assignment.** Every monomorphized template and every function gets a stable `TemplId`/`FnId` keyed by its unique header, and the field-constant/string tables are parsed. Doing this before any body is lowered means `CreateCmp` and `CallFn` can resolve their targets regardless of declaration order.
2. **Body lowering.** Each template/function body is walked bucket by bucket and translated into three-address `Instr`s. Functions are lowered first (templates may call any of them), then templates. Per body, the high-water marks of the register allocators become the frame sizes recorded in `TemplateCode`/`FunctionCode`, and the finished instruction stream is handed to the post-lowering passes.

The lowering work is split across a handful of cooperating modules:

### Expression lowering (`expr.rs`)

The recursive core: turns any IR sub-tree in *value* position (operand of a `ComputeBucket`, right-hand side of a `StoreBucket`) into a `Src` operand — a constant-table reference, a register holding a computed value, or a direct var/signal address. Operand registers are freed back to the allocator as soon as the consuming instruction is emitted.

### Statement lowering (`stmt.rs`)

Handles the buckets that appear at the top level of a body: stores (to vars, signals, and subcomponent inputs), asserts, branches, loops, function calls, logs, and subcomponent creation. This is the largest module; the interesting policies are:

- **Loops** (`lower_loop`): three compilation strategies, chosen per loop:
  - **Unrolled** (`try_unroll_loop`): a *conforming* loop (see below) with a statically known trip count `T` is re-lowered once per iteration with its induction variable bound to a compile-time constant. Every use of the variable folds — index positions become `Addr::Const`, value positions become field constants — and no condition or jump is emitted at all. Unrolling is only committed to if `estimated_body_instrs * T` fits under `UnrollConfig::threshold`. A dependency-free elementwise loop may exceed that budget when its entire expansion compacts to vector instructions (`BinN`/`StoreN`), subject to `UnrollConfig::max_vectorized_loop_size`; otherwise the speculative expansion is rolled back. Per-loop body-size estimates are memoized so nested unrolling doesn't blow up compile time.
  - **Counted, integer-controlled** (`lower_counted_loop`): a conforming loop that stays rolled with a statically known trip count never evaluates a field-domain condition — the variable is an integer mirror (stepped by `IAdd`/`ISub`) and loop exit is an `IJmpIfZero` on a trip counter counting down to zero. When the body never reads the variable in *value* position, the field-side counter disappears entirely and one post-loop `Mov` resyncs the slot (removed by dead-store elimination when unread); otherwise the field counter stays maintained for those reads and only the per-iteration comparison is saved.
  - **Rolled with mirror promotion** (`lower_conforming_loop`): any other conforming loop that stays rolled gets its induction variable *mirrored* into a persistent integer register. The field var slot stays authoritative for value-position reads; index-position reads resolve through the mirror to `Addr::Affine`, so an access like `a[i]` costs an affine addressing mode instead of a runtime field→index conversion each iteration. Descending counters step the mirror with saturating `ISub` (requiring a representable bound; a field-negative bound such as `i >= -5` keeps the fallback).
  - **Fallback** (`lower_fallback_loop`): everything else. The variable stays a plain field slot and index positions go through the ordinary runtime `ToIndex`/`Addr::Dynamic` path — semantically identical to the old stack-based VM.

  *Conformance detection* (`detect_conforming`) is deliberately conservative: simple ascending/descending counters with a constant bound and a constant step, written nowhere else in the body. A loop nested inside a runtime branch is special: the branch condition may be secret-shared, so a data-dependent jump could leak it — such loops are *force-unrolled* regardless of the size threshold, and compilation fails if their trip count isn't statically known.

- **Branches** (`lower_branch`): an `if`/`else` lowers to the `SharedIf`/`SharedIfBit`/`SharedElse`/`SharedEnd` scaffolding. There is no public/shared split at compile time — the VM decides at runtime whether the condition is public (take a real jump) or shared (execute both arms under predication). `SharedIfBit` is emitted when the compiler can prove the condition is already a 0/1 bit, letting the VM skip the zero/non-zero normalization protocol.

- Jumps are emitted with placeholder targets and backpatched once the enclosing construct's extent is known (`CodeGen::patch`).

### Symbolic index lowering (`index.rs`)

Array and subcomponent addresses form their own small IR sub-language (`AddAddress`/`MulAddress`/`ToAddress` nodes over raw `usize` leaves). `eval_index` folds such a sub-tree as far as possible at compile time into an `IndexExpr`:

- **Const** — a literal, or an unrolled loop iteration's induction value;
- **Affine** — `ireg * stride + offset` in a single promoted loop register;
- **Dynamic** — computed at runtime into a fresh integer register (only when neither of the above applies).

This is what makes most array accesses cost a single addressing mode rather than an index recomputed on every access.

### Function-call inlining (`inline.rs`)

`lower_call` splices a small callee's already-optimized bytecode in place of the `CallFn` when that is provably behavior-preserving: the site must never run under a shared predicate (any template site outside branches, or a function that no call chain reaches through a branch arm — a whole-program IR analysis computed before lowering, which also orders function lowering callee-first so callees are spliceable), the callee's single `Ret` must trail the body outside all `Shared*` regions, and accelerator-interceptable names are exempt (see the configuration section). Registers are rebased onto reserved caller blocks and var slots onto a shared per-body scratch range that each site re-initializes like a fresh frame. Besides removing call overhead, this dissolves the optimization barrier a `CallFn` imposes on constant propagation, var forwarding, and CSE.

### Variable environment (`env.rs`)

Tracks, per circom `var` slot, which addressing mode currently applies: a plain field slot, a compile-time constant (during unrolling), or an integer-register mirror (during a rolled conforming loop).

### Register allocation (`regalloc.rs`)

A stack-discipline bump-pointer allocator, one instance for field registers and one for integer registers, reset per body. Registers are only ever freed back to a previously observed mark (never individually), which expression lowering's eager-free convention makes sufficient. The high-water mark becomes the VM frame size. ISA width limits (65535 field registers / 255 integer registers per body) are enforced at allocation time.

## Post-lowering passes (`src/codegen/passes/`)

After a body is lowered, `passes::run` optimizes its instruction stream. Lowering emits **absolute** jump targets, so any pass that deletes instructions must remap every control-flow target; that bookkeeping is centralized in one deletion primitive (`compact`), which every pass expresses itself through by marking which instructions survive.

The pipeline runs the cheap passes **in a loop to a fixed point** — every transformation is monotone (operands only become constants or canonical registers, instructions only simplify, bytecode only disappears), and repeating them exposes second-order wins: a forwarded constant selects a branch, the dead arm makes another definition dead, and so on. Once the fixed point is reached, the batching pass runs once.

Per iteration, in order:

1. **CFG construction & validation** (`passes.rs`). Validates that every jump target is in range, then builds a basic-block control-flow graph. The structured `SharedIf`/`SharedElse`/`SharedEnd` scaffolding is treated as ordinary control flow with both arms as successors.

2. **Sparse conditional constant propagation** (`constant_inputs` + `fold_constants`, `passes.rs`). A worklist dataflow pass computes, per basic block, which field registers hold known constants at entry (facts survive a join only when every incoming path agrees). The folding pass then:
   - evaluates `Bin`/`Neg`/`EqN` instructions with constant operands using the VM's own `PlainDriver` (so folding is bit-for-bit identical to runtime semantics, including field-dependent comparison behavior), rewriting them to `Mov`s of interned constants;
   - propagates known constants into every operand position (asserts, logs, `ToIndex`, branch conditions, vector-instruction lanes);
   - resolves `JmpIfZero` with a constant condition to an unconditional `Jmp` or a fall-through;
   - selects `SharedIf`/`SharedIfBit` branches whose condition is a compile-time constant: `fold_structured_branch` deletes the not-taken arm together with the branch scaffolding, leaving straight-line code;
   - degenerate vector forms (`LoadN`/`BinN` with `n == 1`) are rewritten to their scalar equivalents so later passes see them.

3. **Unreachable-code elimination** (`passes.rs`). A DFS from the entry block drops instructions in blocks that constant-branch selection or jump folding made unreachable.

4. **Fall-through jump removal** (`remove_fallthrough_jumps`, `passes.rs`). Deletes unconditional jumps whose target is the next instruction; compaction can expose more, so this iterates locally until stable.

5. **Register copy propagation** (`copy.rs`). CFG-wide propagation of register-alias facts (`r_dst == r_src`): uses of an alias are rewritten to the canonical source register, and `Mov`s that become self-assignments are deleted. Facts are deliberately limited to register↔register aliases — constants are SCCP's job, and vars/signals are mutable memory handled by the memory pass. Redefining a source register invalidates every alias that captured its old value.

6. **Var-value forwarding** (`memory.rs`, `forward_var_values`). Forward dataflow over the frame-local `Var` slots: a load from a slot whose last store was a known constant becomes that constant, and a load from a slot last stored *from a register* becomes that register (store-to-load forwarding), provided neither the slot nor the register has been written since. Register facts are sameness claims, so — like copy-propagation aliases — they survive CFG joins whenever every path established them. Uses are rewritten against the facts holding before their instruction executes (matching the VM's read-then-write order), so the ubiquitous `Mov Var(x), r; Bin r, Var(x), ...` pattern forwards even though the consumer redefines `r`. Constant-addressed var slots cannot alias signals or another frame, which is what makes this sound. Dynamic/affine writes, calls, and shared-control boundaries conservatively kill facts — in particular, writes under a shared predicate are buffered by the VM until a merge barrier and are not observable by later bytecode in that region, so forwarding through them would be incorrect.

7. **Dead var-store elimination** (`memory.rs`, `eliminate_dead_var_stores`). Backward pass over the same slots: a store to an exact var slot that is provably overwritten before any read is deleted.

8. **Common-subexpression elimination** (`cse.rs`, `eliminate_common_subexpressions`). Block-local value numbering over `Bin`/`Neg`: a computation whose operator and operand *values* match an earlier one in the same block becomes a register `Mov` from the first result, which copy propagation then folds into its users and DCE removes. Under MPC this deletes duplicated protocol operations outright. Value identity uses generation counters (per field/integer register; per exact var/signal slot, with whole-space clobbers for computed addresses, calls, component runs, and predication merge barriers) instead of alias analysis. Removing one of two identical interactive operations is transcript-safe for the same reason DCE of interactive operations is (below).

9. **Dead register-definition elimination** (`dce.rs`). Backward liveness over field and integer registers: arithmetic and loads whose only effect is defining dead registers are removed. Every externally observable instruction is a root (stores to vars/signals, calls, component operations, asserts, logs, returns, control flow). This deliberately includes *interactive MPC arithmetic*: all parties execute an identical compiled program (the VM cross-checks an execution fingerprint before Rep3 runs), so removing the same unused protocol call for every party cannot desynchronize transcripts. This assumption is documented against the current semi-honest VM; an authenticated/malicious protocol may need a stricter policy.

After the fixed point:

10. **Interactive-operation batching** (`batch.rs`, `batch_independent_ops`). Fuses adjacent, dependency-free scalar operations into a single `BinBatch` instruction whose lanes need not use consecutive registers — so one vectorized driver call (one communication round under MPC) replaces several scalar rounds, without gather/scatter bytecode. Batched ops are exactly those the Rep3 driver vectorizes (`Mul`, `BoolAnd`, `Eq`, `Neq`); a batch's lanes share one op. A `Bin` immediately followed by a `Mov` of its result absorbs that `Mov` as the lane's store; a bare `Bin` (e.g. each product of `a*b + c*d`) becomes a store-less lane. The pass intentionally only fuses *adjacent* operations: a corpus experiment showed broader same-block hoisting grouped much more bytecode but did not reduce Rep3 communication (most extra groups contained only one communicating lane). `BatchingConfig::max_batch_size` bounds lane count per batch.

All pass statistics (folded instructions, removed blocks, propagated copies, batch lanes, ...) are emitted per body via `tracing` at trace level.

## Configuration

`CompilerConfig` carries the circom front-end options (version, link libraries, `SimplificationLevel` O0/O1/O2, inspect, verbose), plus:

- `debug` (default `true`): keeps `Assert` instructions in the bytecode; `CompilerConfig::release()` disables it and enables full constraint simplification.
- `unroll: UnrollConfig` — `threshold` (default 4096) is the `body_size * trip_count` budget for unrolling (`0` disables unrolling, `usize::MAX` always unrolls statically-bounded loops); `max_vectorized_loop_size` (default 16384) caps the vectorization bypass for elementwise loops.
- `inline: InlineConfig` — `threshold` (default 64) is the maximum callee body size (in instructions) spliced in place of a `CallFn` (`0` disables inlining); `no_inline` lists function symbols that must keep their calls. **Function accelerators intercept calls by name at run time**, so an inlined call can never be accelerated: the predefined accelerator functions (`sqrt_0`) are never inlined, and the names of any custom function accelerators registered at runtime belong in `no_inline`. Calls are only inlined at sites that provably never run under a shared predicate (templates, and functions no call chain reaches through a branch arm), from callees whose single `Ret` trails the body outside all `Shared*` regions; every `FunctionCode` stays in the program either way, so accelerator binding keeps working for the calls that remain (see `src/codegen/inline.rs`).
- `batching: BatchingConfig` — `max_batch_size` (default 16384) caps `BinBatch` lane counts; `0` disables post-lowering batching.

## Testing

- `tests/kat_progression.rs` compiles the circuits in `tests/circuits/` and asserts known-answer bytecode/behavior as compiler features and passes evolve (loops, branches, functions, arrays, batching, constant folding, ...).
- `tests/accelerator_binding.rs` checks that compiled programs keep the names accelerators bind against.
- The `tests` workspace crate runs the full witness-extension pipeline (compiler2 + vm2) against the shared `test_vectors/`.

# circom-mpc-vm2

Register-based MPC-VM for the circom witness extension.

This crate is the successor of [`circom-mpc-vm`](../circom-mpc-vm), which interprets circom-derived control flow as a *stack-based* bytecode VM. `circom-mpc-vm2` instead executes a flat, three-address instruction stream operating on integer-indexed registers and signal RAM — the classic "stack machine → register machine" rewrite, aimed at removing stack push/pop traffic and opcode-dispatch overhead from the hot path.

The compilation half of the split — circom source in, `CompiledProgram` out — lives in [`circom-mpc-compiler2`](../circom-mpc-compiler2) (GPL-3.0, because of its circom dependencies). This crate owns only the *execution* half and stays under the workspace's MIT/Apache-2.0 licensing: given a `CompiledProgram`, drive it to a finished witness. Programs can also be hand-assembled directly, which is how this crate's own tests (and the runnable example in the crate docs) exercise the VM without the compiler.

## Module map

| Module | Contents |
|---|---|
| `program` | The serializable `CompiledProgram` artifact, `TemplateCode`/`FunctionCode`, `VMConfig`, execution digests |
| `isa` | The instruction set: `Instr`, addressing modes `Src`/`Dst`/`Addr`, `BinOp` |
| `exec` | The execution engine: `Machine`, per-activation `Frame`s, shared-branch `Predication` |
| `driver` | The `VmDriver` trait connecting the VM to an MPC protocol (or plain execution) |
| `drivers` | The three `VmDriver` implementations: `plain`, `rep3`, `taint` |
| `accel` | MPC accelerators: driver-native fast paths for whole components/functions |
| `api` | The supported public API: `WitnessExtension` → `FinalizedWitnessExtension` |
| `profile` | Measurement helpers for protocol-batching decisions |
| `fingerprint` | Streaming helpers for deterministic execution fingerprints |

## The program artifact (`program`)

A `CompiledProgram` is a self-contained, bincode-serializable artifact:

- `templates: Vec<TemplateCode>` / `functions: Vec<FunctionCode>` — one entry per *monomorphized* template / per function, indexed by `TemplId`/`FnId`. Each carries its instruction stream plus frame sizes: number of field registers, integer registers, and var slots to allocate per activation (fixed at compile time by the compiler's register allocator — the VM never grows a frame).
- the field-constant table and log-string table,
- the witness layout: total signal count, main-component input list, output name → `(offset, size)` mapping, and the witness-index → signal-index permutation,
- a `DebugInfo` name table used for error messages and accelerator binding.

`VMConfig` selects runtime behavior: `allow_leaky_logs`, the Rep3 arithmetic↔binary conversion strategy (`a2b_type`), and which predefined accelerators are enabled (initialized from `CIRCOM_MPC_ACCELERATOR_*` environment variables by `VMConfig::default`, overridable in code).

## Instruction set (`isa`)

`Instr` is a three-address ISA: every operand is an addressing mode, not a stack slot, so e.g. `Bin { op, dst, a, b }` reads two operands and writes one register in a single step. Operands (`Src`/`Dst`) address four spaces: field registers (`Reg`, expression temporaries — never predicated), the constant table (`Const`), frame-local var slots (`Var`), and signal RAM (`Signal`, relative to the current component's offset).

Var/signal addresses (`Addr`) come in three modes, resolved as far as possible at compile time:

- `Const(u32)` — absolute slot, the common case;
- `Affine { ireg, stride, offset }` — `iregs[ireg] * stride + offset`, for rolled-loop array stepping;
- `Dynamic(u8)` — fully dynamic index held in an integer register.

Instruction groups:

- **Field ALU**: `Bin` (20 `BinOp`s: arithmetic, comparisons, boolean/bitwise logic, shifts), `Neg`, `Mov`, and array equality `EqN` (backing circom's `a === b` on arrays).
- **Vector ops**: `LoadN`/`StoreN` (consecutive-address block moves through registers), `BinN` (elementwise op over consecutive lanes — one vectorized driver call), and `BinBatch` (*irregular* lanes with arbitrary operand/destination registers, produced by the compiler's post-lowering batching pass; all operands are gathered before any destination is written).
- **Integer unit**: `ISet`/`IAdd`/`IMul`/`ISub` (subtraction saturates at zero — a descending loop mirror's conceptually negative post-final value is never read) on the integer registers that feed `Affine`/`Dynamic` addressing, plus `ToIndex` (public field value → index; errors on shared values).
- **Control flow**: `Jmp`, `JmpIfZero` (field-domain loop back-edges; the condition must be public), `IJmpIfZero` (integer-controlled loops: the compiler emits a trip counter counting down to zero, so counted loops never touch the field domain for control), and the structured branch quartet `SharedIf`/`SharedIfBit`/`SharedElse`/`SharedEnd` (below). `SharedIfBit` marks a condition the compiler proved is already a 0/1 bit, so a shared condition skips the zero/non-zero normalization protocol.
- **Components**: `CreateCmp` (instantiate `count` subcomponents at strided signal offsets), `InputSub`/`OutputSub` (write/read subcomponent signals, optionally through the template's io-map for mapped accesses).
- **Functions**: `CallFn` (arguments from consecutive registers into the callee's `vars[0..n]`), `Ret` (function return, from registers or var slots), `Return` (end of a template body).
- **Debug**: `Assert` (omitted by release compiles), `Log`/`LogStr`/`LogFlush`.

## Execution engine (`exec`)

`Machine` owns the state shared by the whole component tree: signal RAM (index 0 holds the constant 1), the constant table mapped through the driver (`public_from`), the `VMConfig`, the log buffer, and the bound accelerator tables. Each template or function *activation* gets its own `Frame` — field registers, integer registers, and var slots, allocated once from the sizes in `TemplateCode`/`FunctionCode`.

Template and function bodies share a single dispatch implementation (`step`), driven by `run_component`/`run_function` loops acting on a returned `Flow` (continue / jump / return). A `StepCtx` tells `step` which body kind it is executing, since a few instructions are only valid in one (`Return`/`CreateCmp`/`InputSub`/`OutputSub` are template-only; `Ret` is function-only).

Subcomponents follow circom's dataflow model: `CreateCmp` instantiates a child `ComponentInst` (zero-input components run immediately), each `InputSub` counts provided inputs, and the child body runs as soon as its **last** input arrives. Children are owned by the parent's `ComponentInst`, passed into `step` as a parameter so it can recurse into `run_component` without borrow-checker contortions.

### Predication: branching on secrets

A circom `if` whose condition is secret-shared cannot take a real jump — which arm ran would leak the condition. The `SharedIf` family defers the public/shared decision to runtime:

- **Public condition**: `SharedIf` jumps to the else-target when zero, `SharedElse` jumps over the else arm — ordinary control flow, no MPC cost.
- **Shared condition**: `SharedIf` pushes a level onto the `Predication` stack and *falls through into both arms*. `SharedElse` toggles the level's condition — a local subtraction (`outer_acc - acc`), since the level's combined condition is `outer_acc · cur`, so no protocol round is spent even for nested shared branches; `SharedEnd` pops the level.

While any shared level is active, writes to vars and signals are *speculative*: `PendingWrites` records the pre-write value of each destination on first touch, lets the write land immediately (so read-after-write inside the arm sees the branch-local value), and at every control or side-effect boundary merges all dirty destinations in **one** `cmux_many` driver call — `merged = cond ? new : old`. Register writes are never predicated: registers are branch-local temporaries by construction.

Function returns interact with predication too: a `Ret` executed under a shared predicate doesn't return — it *accumulates* `(condition, values)` pairs, and the actual return value is `Σ condᵢ·valᵢ`, merged through one batched `bin_many` multiplication round (falling off the end of the function body with a non-empty accumulator performs the final merge). The accumulated conditions are mutually exclusive by construction, so excluding earlier returns from a new entry's condition is `1 − Σcᵢ`: one multiplication however many entries exist, and entirely local for the final unconditional `Ret`.

Loops, by contrast, must have public conditions (`JmpIfZero` errors on a shared value) — the compiler force-unrolls loops that live under a potentially-shared branch.

## Drivers (`driver`, `drivers`)

Every arithmetic/comparison op in the ISA maps 1:1 to a method on the `VmDriver` trait, so the interpreter loop never branches on "are we running MPC or not" — that choice is fully contained in which driver is plugged in. The trait's associated `VmType` is the value the VM shuffles around: a plain field element, or a public-or-share sum type.

- **`plain::PlainDriver`** — `VmType = F`, executes directly on field elements. For local runs and tests; every other driver embeds one.
- **`rep3::Rep3Driver`** — the 3-party replicated-secret-sharing protocol; `VmType = Rep3VmType` (public `F` or an arithmetic share). Every scalar op matches on operand shapes (`Public∘Public`, `Public∘Arithmetic`, ...), delegating the all-public case to the embedded `PlainDriver` and the rest to the corresponding `mpc_core::protocols::rep3` gadget — so a circuit that happens to run entirely on public values pays no MPC overhead even under a Rep3 witness extension. Construction performs the Rep3 handshake (correlated randomness) and holds **two** independent `(network, state)` pairs so ops needing two concurrent conversions (e.g. `bit_xor` on two shared operands) run them via `mpc_net::join` instead of serializing on one connection.
- **`taint::TaintDriver`** — wraps a `PlainDriver` and tracks per-value shared-ness without any actual MPC. Used to test the VM's visibility rules (what's forbidden on secrets) deterministically, and to collect communication profiles (see `profile`).

**Batching hooks.** Scalar methods have `_many` counterparts with scalar-loop defaults (`bin_many`, `cmux_many`, `open_many`) that protocol drivers override to spend **one communication round per call** instead of one per element. These back the vector instructions (`BinN`, `BinBatch`), the predication merge, and witness finalization. `Rep3Driver`'s `mul_like` is the batching core: public∘public and public∘shared lanes resolve locally, and only the shared∘shared lanes in a batch are reshared together through a single `mul_vec` round, however many there are.

## Accelerators (`accel`)

`MpcAccelerator` is a registry of *component* and *function* accelerators: driver-specific fast paths that replace a whole template/function body instead of interpreting its instructions — e.g. a Rep3-native Poseidon2 permutation with precomputed randomness. The predefined set (`sqrt_0`, `Num2Bits`, `AddBits`, `IsZero`, `Poseidon2`) is toggled through `VMConfig::accelerator`; custom ones are added via `WitnessExtension::register_accelerator_component`/`_function` before the first run.

Registrations are matched against the program **once, by name, at the start of the run** — binding produces `Vec<Option<usize>>` side tables indexed directly by `TemplId`/`FnId`, which `Machine` consults before running a component body or dispatching a call (no per-instruction name lookups). A component accelerator also receives a `TemplateInfo` at binding time so it can decline monomorphizations it doesn't apply to (e.g. Poseidon2's supported state sizes) via its `can_handle` predicate.

## Execution fingerprint (`fingerprint`, `program`)

Before an interactive run, the parties cross-check that they will execute identical code: `VmDriver::compare_execution_fingerprint` receives a blake3 digest binding the schema version, the field modulus, the entire `CompiledProgram` (with the `output_mapping` sorted, since `HashMap` iteration order is randomized), the `VMConfig`, and the bound accelerator tables. The digest is streamed rather than materializing a program-sized buffer, and the builder is passed lazily so plain/local drivers (whose default implementation is a no-op) never pay for the hash. This agreement is also what justifies the compiler's dead-code elimination of unused interactive operations: all parties provably drop the same calls.

## Profiling (`profile`)

Helpers for deciding whether protocol batching is worthwhile: `static_batchability` censuses the bytecode (which `Bin`/`BinN`/`BinBatch` sites use Rep3-vectorizable ops — `Mul`, `BoolAnd`, `Eq`, `Neq`), and `dynamic_batchability` weights that census with an actual execution trace collected by a profiling `TaintDriver` (`Rep3InteractionProfile`: interactive calls and lanes per instruction site).

## Public API (`api`)

`WitnessExtension<F, C>` is the supported entry point: construct with a program, a driver, and a `VMConfig` (`PlainWitnessExtension::new_plain` / `Rep3WitnessExtension::new_rep3` are the convenience paths), optionally register accelerators, then consume it with

- `run(inputs, amount_public_inputs)` — named inputs as a `BTreeMap` (array inputs as `name[0]`, `name[1]`, ... keys), or
- `run_with_flat(values, amount_public_inputs)` — a flat input vector in main-input-list order.

Both fingerprint-check, bind accelerators, execute the main component, and return a `FinalizedWitnessExtension`, from which the shared witness (`into_shared_witness`) or named outputs (`get_output`) are extracted.

## Testing

`tests/` exercises the VM through hand-assembled programs (`straightline.rs`, `functions.rs`, `components.rs`, `shared_if.rs`), the accelerator registry (`accel.rs`), the public API (`api.rs`), and a full three-party Rep3 execution over local networks (`rep3_driver.rs`). End-to-end compiler2+vm2 pipelines live in the workspace-level `tests` crate.

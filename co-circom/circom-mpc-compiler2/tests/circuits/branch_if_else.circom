pragma circom 2.0.0;

// The Task 6 "with else" milestone circuit for `codegen::stmt::lower_branch`: a signal
// (not a compile-time-constant) condition, so this exercises the genuine runtime
// public-vs-shared dispatch the target ISA defers to the VM (`circom_mpc_vm2::isa::Instr`'s
// `SharedIf`/`SharedElse`/`SharedEnd`) rather than anything foldable at compile time. Must
// compile to exactly one `SharedIf`, one `SharedElse`, and one `SharedEnd`.
//
// `<--` (witness-only assignment), not `<==`, in both arms: circom's own type checker
// rejects a `<==` (a *constraint*) whose value depends on a condition that's unknown at
// constraint-generation time (T2005 — R1CS constraints must be the same regardless of
// secret values); branching on a genuinely runtime/shared condition is therefore only
// available to witness computation, exactly matching what `SharedIf`/`SharedElse`/
// `SharedEnd` are for (`circom_mpc_vm2::isa`'s own docs: they belong to witness
// extension, not constraint checking).
template BranchIfElse() {
    signal input a;
    signal output out;
    if (a < 5) {
        out <-- a + 100;
    } else {
        out <-- a + 200;
    }
}

component main = BranchIfElse();

pragma circom 2.0.0;

// Minimal straight-line circuit for the Task 2 milestone test: no loops, branches,
// functions, or subcomponents — just a single multiplication constraint. `multiplier2`
// (the closest circuit in `test_vectors/WitnessExtension/tests/`) has no KAT directory
// and additionally calls `log(...)`, which isn't lowered yet, so this crate carries its
// own tiny fixture instead (see `tests/kat_progression.rs`).
template Mul2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main = Mul2();

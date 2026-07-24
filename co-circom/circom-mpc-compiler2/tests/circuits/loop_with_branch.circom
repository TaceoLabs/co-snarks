pragma circom 2.0.0;

// The Task 6 nested-composition milestone circuit: a conforming `for` loop whose body
// contains a `Branch` (`if`/`else`) that only *reads* the induction variable (as an array
// index, `a[i]`/`out[i]`) and never writes it, so the loop stays conforming
// (`detect_conforming`/`instruction_writes_slot` — see `codegen::stmt`'s module docs) with
// or without unrolling: exercised at both `unroll.threshold: 0` (rolled/mirror-promoted,
// the `Branch` lowers inside `lower_conforming_loop`'s body loop) and `usize::MAX` (fully
// unrolled, the `Branch` lowers once per re-lowered iteration inside `try_unroll_loop`) —
// both must agree on the same witness.
template LoopWithBranch() {
    signal input a[5];
    signal output out[5];
    for (var i = 0; i < 5; i++) {
        if (i < 3) {
            out[i] <== a[i] + 1;
        } else {
            out[i] <== a[i] + 2;
        }
    }
}

component main = LoopWithBranch();

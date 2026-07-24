pragma circom 2.0.0;

// The highest-risk unrolling scenario, per the module docs' "Unrolling" section
// (`codegen::stmt::try_unroll_loop`): a loop that unrolls, followed by a *value-position*
// read of the induction variable after the loop has finished (`final_i <== i;`).
// Unrolling never lowers the loop's own increment store (it binds `i` to a compile-time
// `Binding::ConstUsize` per iteration instead -- see `try_unroll_loop`'s doc comment), so
// without the trailing resync `Mov` it emits once unrolling completes, this would read
// back whatever the last iteration's `ConstUsize` binding happened to be (`4`) instead of
// the loop's real post-loop value (`5`, the first value that fails `i < 5` -- exactly
// what the rolled/mirror-promoted path's own real increment leaves behind). Exercised at
// both `unroll.threshold: 0` (rolled) and `usize::MAX` (fully unrolled) by
// `loop_final_value_post_loop_read_both_thresholds` (`tests/kat_progression.rs`) -- both
// must agree on `final_i == 5`.
//
// NOTE: circom's own front end resolves `i`'s post-loop value to a literal constant
// before this crate's codegen ever runs (confirmed empirically across simplification
// levels and both unroll thresholds), so this circuit alone can't actually exercise the
// resync `Mov` code path -- `final_i <== i;` compiles straight to a constant `Mov`
// regardless of whether the `Mov` in `try_unroll_loop` exists. It's kept as a genuine
// end-to-end correctness check of the source-level scenario; the real regression test for
// the `Mov` itself is `codegen::stmt::tests::
// try_unroll_loop_resyncs_slot_to_final_value_for_post_loop_reads` (white-box, hand-built
// IR, bypassing circom's front end entirely).
template LoopFinalValue() {
    signal input in[5];
    signal output acc_out;
    signal output final_i;
    var acc = 0;
    var i;
    for (i = 0; i < 5; i++) {
        acc += in[i];
    }
    final_i <== i;
    acc_out <== acc;
}

component main = LoopFinalValue();

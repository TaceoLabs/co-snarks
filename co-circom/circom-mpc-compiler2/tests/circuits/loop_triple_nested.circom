pragma circom 2.0.0;

// A 3-deep nest of conforming loops (`i` outer, `j` middle, `k` innermost), all small
// enough to unroll entirely under a forced (`usize::MAX`) unroll threshold. This is the
// regression circuit for `CodeGen::unroll_estimate_cache`
// (`codegen::stmt::try_unroll_loop`'s memoization): without it, estimating whether the
// innermost loop is worth unrolling gets redone from scratch on every single iteration of
// every enclosing loop, so the number of (thrown-away) estimation passes grows with the
// *product* of the enclosing trip counts, not just their sum -- unbounded overhead growth
// with nesting depth. Paired with `loop_triple_nested_wide_outer.circom` (same shape, a
// bigger *outer* trip count) by
// `nested_unroll_estimation_does_not_scale_with_outer_trip_count`
// (`codegen::stmt`'s unit tests), which asserts both fixtures trigger the exact same
// number of estimation passes -- i.e. that count doesn't scale with the outer loop's own
// trip count.
template LoopTripleNested() {
    signal input a[2][2][2];
    signal output out;
    var acc = 0;
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 2; j++) {
            for (var k = 0; k < 2; k++) {
                acc += a[i][j][k];
            }
        }
    }
    out <== acc;
}

component main = LoopTripleNested();

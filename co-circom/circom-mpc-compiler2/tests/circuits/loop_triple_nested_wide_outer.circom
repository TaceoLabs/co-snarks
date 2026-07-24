pragma circom 2.0.0;

// Identical to `loop_triple_nested.circom` except for its *outer* loop's trip count (6
// instead of 2) — the middle/inner trip counts are unchanged. Used by
// `nested_unroll_estimation_is_memoized_per_lexical_loop`
// (`codegen::stmt`'s unit tests) to confirm that the number of
// `estimate_unrolled_body` calls doesn't scale with the *outer* loop's own trip count:
// per `CodeGen::unroll_estimate_cache`'s doc comment, an ancestor that decides to unroll
// for real always re-lowers its body with the same (`ConstUsize`) binding kind on every
// one of its iterations, so a nested loop's cached estimate — once populated on the first
// such iteration — is safe to reuse on every other one, regardless of how many there are.
template LoopTripleNestedWideOuter() {
    signal input a[6][2][2];
    signal output out;
    var acc = 0;
    for (var i = 0; i < 6; i++) {
        for (var j = 0; j < 2; j++) {
            for (var k = 0; k < 2; k++) {
                acc += a[i][j][k];
            }
        }
    }
    out <== acc;
}

component main = LoopTripleNestedWideOuter();

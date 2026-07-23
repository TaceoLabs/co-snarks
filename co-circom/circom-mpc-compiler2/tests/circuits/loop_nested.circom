pragma circom 2.0.0;

// Nested conforming loops sharing the outer counter across an entire inner loop: `out[i]`
// is written *after* the inner `j` loop has fully run (allocated its own persistent
// `ireg`, iterated, and released it). This is the regression circuit for "nested loops
// must not clobber the outer's `ireg` binding" (`codegen::stmt::lower_loop`'s module
// docs, "Where the persistent integer register lives") -- if the outer loop's mirror
// register were freed or overwritten by the inner loop's own allocation, `out[i]` would
// resolve to the wrong `Addr::Affine` (or a stale/incorrect one), producing a wrong
// witness even though every individual constraint still type-checks.
template LoopNested() {
    signal input a[3][4];
    signal output out[3];
    var sum;
    for (var i = 0; i < 3; i++) {
        sum = 0;
        for (var j = 0; j < 4; j++) {
            sum += a[i][j];
        }
        out[i] <== sum;
    }
}

component main = LoopNested();

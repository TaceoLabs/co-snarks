pragma circom 2.0.0;

// sum_first5_scaled(scale) = sum_{i=0}^{4} (i + bonus) * scale, bonus = 10 on even i, 0
// on odd i -- a function body containing a conforming `for` loop (literal bound `5`,
// so it promotes/unrolls exactly like a template's would) whose body contains an
// if/else, exercising the same statement-lowering machinery (loops, induction-variable
// promotion, branches) inside a function frame instead of a template's. `scale` is a
// genuine runtime (signal-derived) function argument -- only the loop's own bound is a
// compile-time literal, so this doesn't merely restate the recursion/multi-return
// fixtures' shapes.
function sum_first5_scaled(scale) {
    var acc = 0;
    for (var i = 0; i < 5; i++) {
        if (i % 2 == 0) {
            acc = acc + (i + 10) * scale;
        } else {
            acc = acc + i * scale;
        }
    }
    return acc;
}

template SumFirst5Scaled() {
    signal input scale;
    signal output out;
    var s = sum_first5_scaled(scale);
    out <-- s;
}

component main = SumFirst5Scaled();

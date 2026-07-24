pragma circom 2.0.0;

// square(x) = x^2, called from inside larger expressions (never itself the sole RHS of
// a store) -- Task 7's "function call inside an expression" milestone: a CallBucket's
// result, once landed in a `var`, composes with ordinary expression lowering exactly
// like any other value, and a call's own argument can itself be a non-trivial
// expression.
function square(x) {
    return x * x;
}

template CallInExpr() {
    signal input a;
    signal input b;
    signal output sum_of_squares;
    signal output square_of_sum;

    var s = square(a) + square(b);
    sum_of_squares <-- s;

    var t = square(a + b);
    square_of_sum <-- t;
}

component main = CallInExpr();

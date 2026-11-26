pragma circom 2.0.0;

// Asserts inside the branches of an if with a secret-shared condition.
// in[0] selects the branch, the asserts compare in[1] and in[2].

function check_equal(a, b) {
    assert(a == b);
    return a + 1;
}

template SharedIfAssert() {
    signal input in[3];
    signal output out;
    var res = 0;
    if (in[0] == 1) {
        // assert inside a function that is called in the branch
        res = check_equal(in[1], in[2]);
    } else {
        assert(in[1] != in[2]);
        res = in[2] + 2;
    }
    out <-- res;
}

component main = SharedIfAssert();

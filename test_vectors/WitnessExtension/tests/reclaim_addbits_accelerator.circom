pragma circom 2.0.0;

/**
 * Add N bit numbers together
 * copied in from: https://github.com/iden3/circomlib/blob/master/circuits/binsum.circom
 * but rewritten slightly to reduce the final number of wires & labels
 * and possibly look at reducing the number of constraints
 */
template AddBits(BITS) {
    signal input a[BITS];
    signal input b[BITS];
    signal output out[BITS];
    signal carrybit;

    var lin = 0;
    var lout = 0;

    var k;
    var j = 0;

    var e2;

    // create e2 which
    // is the numerical sum of 2^k
    e2 = 1;
    for (k = BITS - 1; k >= 0; k--) {
        lin += (a[k] + b[k]) * e2;
        e2 *= 2;
    }

    e2 = 1;
    for (k = BITS - 1; k >= 0; k--) {
        out[k] <-- (lin >> j) & 1;
        // Ensure out is binary
        out[k] * (out[k] - 1) === 0;
        lout += out[k] * e2;
        e2 *= 2;
        j += 1;
    }

    carrybit <-- (lin >> j) & 1;
    // Ensure out is binary
    carrybit * (carrybit - 1) === 0;
    lout += carrybit * e2;

    // Ensure the sum matches
    lin === lout;
}

template Main() {
    signal input a[32];
    signal input b[32];
    signal output out[32];

    component add_bits = AddBits(32);

    for (var i = 0; i < 32; i++) {
        add_bits.a[i] <== a[i];
        add_bits.b[i] <== b[i];
    }
    for (var i = 0; i < 32; i++) {
        out[i] <== add_bits.out[i];
    }
}

component main = Main();

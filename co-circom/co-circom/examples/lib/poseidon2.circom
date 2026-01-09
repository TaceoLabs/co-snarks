pragma circom 2.2.2;

include "poseidon2_constants.circom";

template Acc(t) {
    signal input in[t];
    signal output out;
    signal sums[t];
    sums[0] <== in[0];
    for (var i = 1;i<t;i++) {
        sums[i] <== sums[i-1] + in[i];
    }
    out <== sums[t-1];
}

template ExternalMatMul2 {
    signal input in[2];
    signal output out[2];
    signal sum <== in[0] + in[1];
    out[0] <== in[0] + sum;
    out[1] <== in[1] + sum;
}

template ExternalMatMul3 {
    signal input in[3];
    signal output out[3];
    signal sum <== in[0] + in[1] + in[2];
    out[0] <== in[0] + sum;
    out[1] <== in[1] + sum;
    out[2] <== in[2] + sum;
}

template ExternalMatMul4 {
    signal input in[4];
    signal output out[4];

    signal double_in1 <== 2 * in[1];
    signal double_in3 <== 2 * in[3];

    signal t_0 <== in[0] + in[1];
    signal t_1 <== in[2] + in[3];

    signal quad_t_0 <== 4 * t_0;
    signal quad_t_1 <== 4 * t_1;

    signal t_2 <== double_in1 + t_1;
    signal t_3 <== double_in3 + t_0;
    signal t_4 <== quad_t_1 + t_3;
    signal t_5 <== quad_t_0 + t_2;

    out[0] <== t_3 + t_5;
    out[1] <== t_5;
    out[2] <== t_2 + t_4;
    out[3] <== t_4;
}

template ExternalMatMulT(t) {
    signal input in[t];
    signal output out[t];

    if (t == 2) {
        out <== ExternalMatMul2()(in);
    } else if (t == 3) {
        out <== ExternalMatMul3()(in);
    } else if (t== 4) {
        out <== ExternalMatMul4()(in);
    } else {
        var amount_mds = t / 4;
        component mds[amount_mds];

        for (var i = 0;i<amount_mds;i++) {
            var offset = 4 * i;
            mds[i] = ExternalMatMul4();
            for (var j = 0;j<4;j++) {
                mds[i].in[j] <== in[offset + j];
            }
        }

        component accs[4];
        for (var l = 0;l<4;l++) {
            accs[l] = Acc(amount_mds);
            accs[l].in[0] <== mds[0].out[l];
            for (var j = 1;j<amount_mds;j++) {
                accs[l].in[j] <== mds[j].out[l];
            }
        }

        for (var i = 0;i<amount_mds;i++) {
            for (var j = 0;j<4;j++) {
                out[i * 4 + j] <== mds[i].out[j] + accs[j].out;
            }
        }
    }
}

template InternalMatMul2() {
    signal input in[2];
    signal output out[2];

    signal sum <== in[0] + in[1];
    out[0] <== in[0] + sum;
    out[1] <== 2 * in[1] + sum;
}

template InternalMatMul3() {
    signal input in[3];
    signal output out[3];

    signal sum <== in[0] + in[1] + in[2];
    out[0] <== in[0] + sum;
    out[1] <== in[1] + sum;
    out[2] <== 2 * in[2] + sum;
}

template InternalMatMulT(t) {
    signal input in[t];
    signal output out[t];

    if (t == 2) {
        out <== InternalMatMul2()(in);
    } else if (t == 3) {
        out <== InternalMatMul3()(in);
    } else {
        // Load the diagonal for the inner matrix multiplication.
        // It is the same for every round, so we could theoretically
        // load it once and pass it as a template parameter.
        // However, for widths t = 2 and t = 3 there is no diagonal,
        // so we opted to call this function each round. This may add some
        // overhead with our standard witness extension, but the graph
        // compiler hopefully eliminates this call completely.
        var diag[t] = load_diag(t);
        signal acc <== Acc(t)(in);
        for (var i = 0;i<t;i++) {
            out[i] <== in[i] * diag[i] + acc;
        }
    }
}

template Sbox_e() {
    signal input in;
    signal output out;
    signal square <== in * in;
    signal pow_4 <== square * square;
    out <== pow_4 * in;
}

template Sbox(t) {
    signal input in[t];
    signal output out[t];

    for (var i = 0;i<t;i++) {
        out[i] <== Sbox_e()(in[i]);
    }
}

template FullRound(t) {
    signal input in[t];
    signal input RC[t];
    signal output out[t];

    // add full round constants
    signal linear_layer[t];
    for (var i=0;i<t;i++) {
        linear_layer[i] <== in[i] + RC[i];
    }
    // apply sbox for all elements
    signal sbox[t] <== Sbox(t)(linear_layer);

    // apply external mds matrix
    out <== ExternalMatMulT(t)(sbox);
}

template PartialRound(t) {
    signal input in[t];
    signal input RC;
    signal output out[t];

    // add rc to first element
    signal linear_layer <== in[0] + RC;

    // apply sbox to first element
    signal sbox <== Sbox_e()(linear_layer);

    // apply internal mds matrix
    component internal_mm = InternalMatMulT(t);
    internal_mm.in[0] <== sbox;
    for (var i = 1;i<t;i++) {
        internal_mm.in[i] <== in[i];
    }
    out <== internal_mm.out;
}

template Poseidon2(t) {
    // sanity check that we only have valid state sizes
    assert(t == 2 || t == 3 || t == 4 || t == 8 || t == 12 || t == 16);

    signal input in[t];
    signal output out[t];

    // load amount partial rounds
    var partial_rounds = amount_partial_rounds(t);

    // load round constants
    var rc_full1[4][t] = load_rc_full1(t);
    var rc_partial[partial_rounds] = load_rc_partial(t);
    var rc_full2[4][t] = load_rc_full2(t);

    signal state[9+partial_rounds][t];

    // Outer matrix mul
    state[0] <== ExternalMatMulT(t)(in);

    // First 4 full rounds
    for (var i = 0;i<4;i++) {
        state[i+1] <== FullRound(t)(state[i], rc_full1[i]);
    }

    // Partial Rounds
    for (var i = 0;i<partial_rounds;i++) {
        state[i+5] <== PartialRound(t)(state[i+4], rc_partial[i]);
    }

    // Second 4 full rounds
    for (var i = 0;i<4;i++) {
        state[i+5+partial_rounds] <== FullRound(t)(state[i+4+partial_rounds], rc_full2[i]);
    }

    out <== state[8+partial_rounds];
}
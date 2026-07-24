pragma circom 2.0.0;

template LoopCarriedProduct() {
    signal input x;
    signal input factors[4];
    signal output out[5];

    out[0] <== x;
    for (var i = 0; i < 4; i++) {
        out[i + 1] <== out[i] * factors[i];
    }
}

component main = LoopCarriedProduct();

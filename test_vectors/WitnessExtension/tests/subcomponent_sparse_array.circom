pragma circom 2.0.0;

template AddConst(c) {
    signal input in;
    signal output out;
    out <== in + c;
}

template Main() {
    signal input x;
    signal output y1;
    signal output y2;
    component c[3];
    for (var i = 1; i < 3; i++) {
        c[i] = AddConst(5);
        c[i].in <== x + i;
    }
    y1 <== c[1].out;
    y2 <== c[2].out;
}

component main = Main();

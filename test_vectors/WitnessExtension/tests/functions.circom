
pragma circom 2.0.0;

function sub(x, y) {
    assert(x > y);
    return x - y;
}


template Pow(N) {
    signal input a;
    signal output b;
    b <== sub(a,N);    
}

component main = Pow(3);
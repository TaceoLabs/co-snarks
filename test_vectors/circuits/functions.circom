
pragma circom 2.0.0;

function pow(x, exp) {
    return x * exp;
}


template Pow(N) {
    signal input a;
    signal output b;

    b <== pow(a,N);    
}

component main = Pow(3);
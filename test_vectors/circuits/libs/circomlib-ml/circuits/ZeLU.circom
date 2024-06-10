pragma circom 2.0.0;

// Poly activation layer: https://arxiv.org/abs/2011.05530
// n = 10 to the power of the number of decimal places
// out and remainder are from division by n so out has the same number of decimal places as in
template ZeLU (n) {
    signal input in;
    signal input out;
    signal input remainder;

    assert(remainder < n);
    
    signal tmp;
    tmp <== in * in + n*in;
    out * n + remainder === tmp;
}

// component main { public [ out ] } = ZeLU(10**9);

/* INPUT = {
    "in":  "123456789",
    "out": "138698367",
    "remainder": "750190521"
} */
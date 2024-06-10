pragma circom 2.0.0;

// Polynomial approximation for the tanh layer
// 0.006769816 + 0.554670504 * x - 0.009411195 * x**2 - 0.014187547 * x**3
// 6769816 + 554670504 * x - 9411195 * x**2 - 14187547 * x**3
// 6769816 + x * (554670504 - 9411195 * x - 14187547 * x**2)
// n = 10 to the power of the number of decimal places
// out and remainder are from division by n**2 so out has the same number of decimal places as in
template Zanh (n) {
    signal input in;
    signal input out;
    signal input remainder;
    
    assert(remainder < (n**2) * (10**9));

    signal tmp;

    tmp <== 554670504 * n**2 - 9411195 * n * in - 14187547 * in * in;
    // log(6769816 * n**3 + in * tmp);
    out * (n**2) * (10**9) + remainder === 6769816 * n**3 + in * tmp;
}

// component main { public [ out ] } = Zanh(10**9);

/* INPUT = {
    "in":  "123456789",
    "out": "750775175",
    "remainder": "35162208611038149371400257"
} */
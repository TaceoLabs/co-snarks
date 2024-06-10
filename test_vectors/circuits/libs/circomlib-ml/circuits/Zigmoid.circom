pragma circom 2.0.0;

// Polynomial approximation for the sigmoid layer
// 0.502073021 + 0.198695283 * x - 0.001570683 * x**2 - 0.004001354 * x**3
// 502073021 + 198695283 * x - 1570683 * x**2 - 4001354 * x**3
// 502073021 + x * (198695283 - 1570683 * x - 4001354 * x**2)
// n = 10 to the power of the number of decimal places
// out and remainder are from division by n**2 so out has the same number of decimal places as in
template Zigmoid (n) {
    signal input in;
    signal input out;
    signal input remainder;
    
    assert(remainder < (n**2) * (10**9));

    signal tmp;

    tmp <== 198695283 * n**2 - 1570683 * n * in - 4001354 * in * in;
    // log(502073021 * n**3 + in * tmp);
    out * (n**2) * (10**9) + remainder === 502073021 * n**3 + in * tmp;
}

// component main { public [ out ] } = Zigmoid(10**9);

/* INPUT = {
    "in":  "123456789",
    "out": "526571833",
    "remainder": "686713237479944887069368574"
} */
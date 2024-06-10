pragma circom 2.0.0;

// BatchNormalization layer for 2D inputs
// a = gamma/(moving_var+epsilon)**.5
// b = beta-gamma*moving_mean/(moving_var+epsilon)**.5
// n = 10 to the power of the number of decimal places
template BatchNormalization2D(nRows, nCols, nChannels, n) {
    signal input in[nRows][nCols][nChannels];
    signal input a[nChannels];
    signal input b[nChannels];
    signal input out[nRows][nCols][nChannels];
    signal input remainder[nRows][nCols][nChannels];

    for (var i=0; i<nRows; i++) {
        for (var j=0; j<nCols; j++) {
            for (var k=0; k<nChannels; k++) {
                assert(remainder[i][j][k] < n);
                out[i][j][k] * n + remainder[i][j][k] === a[k]*in[i][j][k]+b[k];
            }
        }
    }
}

// component main { public [ out ] } = BatchNormalization2D(1, 1, 1, 1000);

/* INPUT = {
    "in":  ["123"],
    "a": ["234"],
    "b": ["345678"],
    "out": ["374"],
    "remainder": ["460"]
} */
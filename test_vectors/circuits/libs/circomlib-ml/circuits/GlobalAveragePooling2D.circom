pragma circom 2.0.0;

include "./GlobalSumPooling2D.circom";

// GlobalAveragePooling2D layer, might lose precision compared to GlobalSumPooling2D
template GlobalAveragePooling2D (nRows, nCols, nChannels) {
    signal input in[nRows][nCols][nChannels];
    signal input out[nChannels];
    signal input remainder[nChannels];

    component globalSumPooling2D = GlobalSumPooling2D (nRows, nCols, nChannels);

    for (var i=0; i<nRows; i++) {
        for (var j=0; j<nCols; j++) {
            for (var k=0; k<nChannels; k++) {
                globalSumPooling2D.in[i][j][k] <== in[i][j][k];
            }
        }
    }

    for (var k=0; k<nChannels; k++) {
        assert (remainder[k] < nRows*nCols);
        out[k] * nRows * nCols + remainder[k] === globalSumPooling2D.out[k];
    }
}
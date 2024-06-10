pragma circom 2.0.0;

include "./util.circom";

// GlobalMaxPooling2D layer
template GlobalMaxPooling2D (nRows, nCols, nChannels) {
    signal input in[nRows][nCols][nChannels];
    signal input out[nChannels];

    component max[nChannels];

    for (var k=0; k<nChannels; k++) {
        max[k] = Max(nRows*nCols);
        for (var i=0; i<nRows; i++) {
            for (var j=0; j<nCols; j++) {
                max[k].in[i*nCols+j] <== in[i][j][k];
            }
        }
        out[k] === max[k].out;
    }
}
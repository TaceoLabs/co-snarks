pragma circom 2.1.1;

include "./PointwiseConv2D.circom";
include "./DepthwiseConv2D.circom";

// Separable convolution layer with valid padding.
// Quantization is done by the caller by multiplying float values by 10**exp.
template SeparableConv2D (nRows, nCols, nChannels, nDepthFilters, nPointFilters, depthKernelSize, strides, n) {
    var outRows = (nRows-depthKernelSize)\strides+1;
    var outCols = (nCols-depthKernelSize)\strides+1;

    signal input in[nRows][nCols][nChannels];
    signal input depthWeights[depthKernelSize][depthKernelSize][nDepthFilters]; // weights are 3d because depth is 1
    signal input depthBias[nDepthFilters];
    signal input depthRemainder[outRows][outCols][nDepthFilters];
    signal input depthOut[outRows][outCols][nDepthFilters];

    signal input pointWeights[nChannels][nPointFilters]; // weights are 2d because depthKernelSize is one
    signal input pointBias[nPointFilters];

    signal input pointRemainder[outRows][outCols][nPointFilters];
    signal input pointOut[outRows][outCols][nPointFilters];

    component depthConv = DepthwiseConv2D(nRows, nCols, nChannels, nDepthFilters, depthKernelSize, strides, n);
    component pointConv = PointwiseConv2D(outRows, outCols, nDepthFilters, nPointFilters, n);

    for (var filter=0; filter<nDepthFilters; filter++) {
        for (var x=0; x<depthKernelSize; x++) {
            for (var y=0; y<depthKernelSize; y++) {
                depthConv.weights[x][y][filter] <== depthWeights[x][y][filter];
            }
        }
        depthConv.bias[filter] <== depthBias[filter];
    }

    for (var row=0; row < nRows; row++) {
        for (var col=0; col < nCols; col++) {
            for (var channel=0; channel < nChannels; channel++) {
                depthConv.in[row][col][channel] <== in[row][col][channel];
            }
        }
    }
    for (var row=0; row < outRows; row++) {
        for (var col=0; col < outCols; col++) {
            for (var filter=0; filter < nDepthFilters; filter++) {
                depthConv.remainder[row][col][filter] <== depthRemainder[row][col][filter];
                depthConv.out[row][col][filter] <== depthOut[row][col][filter];
                pointConv.in[row][col][filter] <== depthOut[row][col][filter];

            }
        }
    }
    for (var filter=0; filter < nPointFilters; filter++) {
        for (var channel=0; channel < nChannels; channel++) {
            pointConv.weights[channel][filter] <== pointWeights[channel][filter];
        }
        pointConv.bias[filter] <== pointBias[filter];
    }
    for (var row=0; row < outRows; row++) {
        for (var col=0; col < outCols; col++) {
            for (var filter=0; filter < nPointFilters; filter++) {
                pointConv.remainder[row][col][filter] <== pointRemainder[row][col][filter];
                pointConv.out[row][col][filter] <== pointOut[row][col][filter];
            }
        }
    }
}

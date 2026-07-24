pragma circom 2.0.0;

template SharedBranchDescendingLoop() {
    signal input cond;
    signal input a[4];
    signal output out;

    var sum = 0;
    if (cond) {
        for (var i = 4; i > 0; i--) {
            sum += a[i - 1];
        }
    }
    out <-- sum;
}

component main = SharedBranchDescendingLoop();

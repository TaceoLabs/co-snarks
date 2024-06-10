pragma circom 2.0.0;


function someValue(x) {
    if (x == 100) {
        if (x + 1 == 95) {
            if (x == 75) {
                log("1)", x+1);
                return x+1;
            } else {
                log("2)", x+1);
                return x+2;
            }
        } else if (x-1 == 95) {
            log("3)", x+1);
            return x+3;
        } else {
            log("4)", x+1);
            return x+4;
        }
    } else if (x == 50) {
        log("5)", x+1);
        return x+5;
    } else if (x == 25) {
        log("6)", x+1);
        return x+6;
    } else  {
        log("7)", x+1);
        return x+7;
    }
} 

template Main(t) {
    signal input in[t];
    signal output b;
    signal val;
    val <-- someValue(in[0]);
    b<== in[0] + val;
}

component main = Main(1);
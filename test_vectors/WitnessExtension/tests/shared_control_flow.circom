pragma circom 2.0.0;

include "libs/comparators.circom";

function evenAnotherFunction(x) {
    if (x != 0) {
        return 42;
    }
    x += 1;
    x *= 2;
    return x;
}

function anotherFunction(x) {
    var y = 0;
    if (x == 75) {
        y = x + 10;
    }
    return evenAnotherFunction(y);
}

function someValue(x, y) {
    if (x >= 51) {
        if (x + 1 == 95) {
            if (x == 75) {
                return x+1;
            } else {
                return x+2;
            }
        } else if (x-1 == 95) {
            return x+3;
        } else {
            return anotherFunction(x);
        }
    } else if (x == 50) {
        return x+5;
    } else if (x == 25) {
        return x+6;
    } 
    if (y != 4) {
        log("I should never be called!!!");
        assert(0);
        return 0;
    } else {
        return x+8;
    }
    
} 

template Main(t) {
    signal input in[1];
    signal output b;
    signal val;
    val <-- someValue(in[0], t);
    b<== in[0] + val;
}

component main = Main(4);
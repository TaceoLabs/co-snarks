pragma circom 2.0.0;

function evenAnotherFunction(x) {
    var arr[5] = [1,2,3,4,5];
    if (x != 0) {
        for (var i =0;i<5;i++) {
            arr[i] += x;
        }
        return arr;
    }
    x += 1;
    x *= 2;
    return [x,x+1];
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
                return [x+1, 3];
            } else {
                return [x+2, 4];
            }
        } else if (x-1 == 95) {
            return anotherFunction(x);
        } else {
            var ret_vals[5] = anotherFunction(x);
            return [ret_vals[3], ret_vals[4]];
        }
    } else if (x == 50) {
        return [x+4, 5];
    } else if (x == 25) {
        return [x+5, 6];
    } 
    if (y != 4) {
        log("I should never be called!!!");
        assert(0);
        return [0,0];
    } else {
        return [x+12, 7];
    }
    
} 

template Main(t) {
    signal input in[1];
    signal output b;
    signal val[2];
    signal acc;
    val <-- someValue(in[0], t);
    acc <== in[0] + val[0];
    b<== acc + val[1];
}

component main = Main(4);
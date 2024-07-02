pragma circom 2.0.0;

// From circuit folder: circom guessing-game/winner.circom --r1cs

include "../libs/utils.circom";

template Winner(nInputs, N) {
    signal input inp_address[nInputs];
    signal input commitments[nInputs];
    signal input inp_guess[nInputs];
    signal input inp_r[nInputs];
    signal output win_guess;
    signal output win_address;

    // Calculate the commitments
    component commit[nInputs];
    for (var i = 0; i < nInputs; i++) {
        commit[i] = Commit2();
        commit[i].input0 <== inp_guess[i];
        commit[i].input1 <== inp_address[i];
        commit[i].r <== inp_r[i];
        commitments[i] === commit[i].c;
    }

    // Calculate the highest guess and its id
    component highest = UniqueHighestValWithId(nInputs, N);
    highest.inputs <== inp_guess;
    highest.ids <== inp_address;
    win_guess <== highest.outp;
    win_address <== highest.outp_id;
    log("win guess: ", win_guess);
}

component main {public [inp_address, commitments]} = Winner(10, 7);

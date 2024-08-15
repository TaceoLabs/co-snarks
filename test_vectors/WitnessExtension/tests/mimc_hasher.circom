pragma circom 2.0.0;

include "mimc.circom";

//compiler panics with n_rounds=1
component main = MultiMiMC7(3,91);

use poseidon2::bn254::permutation;

//-8724675007627701394367576277397137785970603800817593955743442482136808733218
fn main(plains: [Field; 8]) -> pub Field {
    permutation::t8(plains)[0]
}

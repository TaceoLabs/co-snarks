use poseidon::bn254::permutation;

//11310881426863758969673455627751586109555621418509937881456378136748013877094
fn main(plains: [Field; 8]) -> pub Field {
    permutation::t_8(plains)[0]
}

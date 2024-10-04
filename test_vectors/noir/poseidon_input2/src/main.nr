use dep::poseidon;

//11310881426863758969673455627751586109555621418509937881456378136748013877094
fn main(input1: [Field; 4], input2: [Field; 4]) -> pub Field {
    let plains = [input1[0], input1[1], input1[2], input1[3], input2[0], input2[1], input2[2], input2[3]];
    poseidon::bn254::hash_8(plains)
}

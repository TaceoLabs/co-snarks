use poseidon::bn254::permutation;

//11310881426863758969673455627751586109555621418509937881456378136748013877094
fn main(x: Field, y: Field) -> pub Field {
    assert(x != y);
    permutation::t_2([x, y])[0]
}

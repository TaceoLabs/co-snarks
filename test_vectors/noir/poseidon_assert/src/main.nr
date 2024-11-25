use dep::poseidon;

//11310881426863758969673455627751586109555621418509937881456378136748013877094
fn main(x: Field, y: Field) -> pub Field {
    assert(x != y);
    poseidon::bn254::hash_2([x, y])
}

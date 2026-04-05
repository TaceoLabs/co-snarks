// Two private inputs multiplied together -- forces shared x shared MPC multiplication.
fn main(x: Field, y: Field) {
    let product = x * y;
    assert(product != 0);
}

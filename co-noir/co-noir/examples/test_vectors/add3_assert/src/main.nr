fn main(x: Field, y: pub Field, z: pub Field, check: pub Field) -> pub Field {
    let addition = x + y + z;
    assert(addition == check);
    addition
}

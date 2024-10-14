fn main(x: Field, y: pub Field, z: pub Field) -> pub Field {
    x + y + z
}

#[test]
fn test_main() {
    let addition = main(1, 2, 3);
    assert(addition == 6);
}

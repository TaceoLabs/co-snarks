unconstrained fn add(x: Field, y: Field) -> Field {
    x + y
}

fn main(x: Field, y: Field, z: pub Field) {
    assert(
        ///Safety: is safe
        unsafe { add(x, y) }
            == z,
    );
}

#[test]
fn test_main() {

    // Uncomment to make test fail
    // main(1, 1);
}

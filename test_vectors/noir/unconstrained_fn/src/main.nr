unconstrained fn add(x: u32, y: u32) -> u32 {
    x + y
}

fn main(x: u32, y: u32, z: pub u32) {
    // Safety: add is safe
    assert(unsafe { add(x, y) } == z);
}

#[test]
fn test_main() {

    // Uncomment to make test fail
    // main(1, 1);
}

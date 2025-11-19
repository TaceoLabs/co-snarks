unconstrained fn not(x: u32) -> u32 {
    !x
}

fn main(x: u32, z: pub u32) {
    // Safety: not is safe
    assert(unsafe { not(x) } == z);
}

#[test]
fn test_main() {

    // Uncomment to make test fail
    // main(1, 1);
}

fn main(x: Field, y: pub Field, z: pub Field, check: pub Field) -> pub Field {
    let addition=x + y + z;
     assert(addition == check);
     addition
}

// #[test]
// fn test_main() {
//     let addition = main(1, 2, 3);
//     assert(addition == 6);
// }

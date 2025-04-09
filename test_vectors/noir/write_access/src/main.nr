fn main(x: Field, y: pub Field, z: Field) -> pub Field {
    let mut block = [x, y];
    let test = &mut block;
    test[x as u32] = z;
    z + test[x as u32]
}

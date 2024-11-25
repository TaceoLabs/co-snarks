fn main(x: Field, bytes: [u8; 32]) {
    assert(Field::from_be_bytes::<32>(bytes) == x);
}


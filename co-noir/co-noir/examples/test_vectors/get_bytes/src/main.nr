fn main(x: Field) -> pub [u8; 32] {
    ///Safety: get_bytes is safe
    unsafe {
        get_bytes(x)
    }
}

pub unconstrained fn get_bytes(x: Field) -> [u8; 32] {
    x.to_be_bytes()
}

fn main(negative: bool, truncated: [u8; 32]) {
    let mut new_x: Field = Field::from_be_bytes::<32>(truncated);
    // Flip back sign if the output is negative
    if negative {
        new_x = 21888242871839275222246405745257275088548364400416034343698204186575808495616
            - new_x
            + 1;
    }
}


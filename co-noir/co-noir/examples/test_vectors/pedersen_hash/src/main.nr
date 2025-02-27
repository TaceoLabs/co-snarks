fn main(x: Field, y: Field) -> pub Field {
    std::hash::pedersen_hash([x, y])
}

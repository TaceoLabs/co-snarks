fn main(a: Field, b: Field, c: Field, d: Field, e: Field, f: Field) -> pub Field {
    std::hash::pedersen_hash([a, b, c, d, e, f])
}

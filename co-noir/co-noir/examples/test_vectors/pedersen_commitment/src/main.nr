fn main(
    a: Field,
    b: Field,
    c: Field,
    d: Field,
    e: Field,
    f: Field,
) -> pub std::embedded_curve_ops::EmbeddedCurvePoint {
    std::hash::pedersen_commitment([a, b, c, d, e, f])
}

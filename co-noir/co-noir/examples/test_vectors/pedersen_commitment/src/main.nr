fn main(x: Field, y: Field) -> pub std::embedded_curve_ops::EmbeddedCurvePoint {
    std::hash::pedersen_commitment([x, y])
}

use std::embedded_curve_ops::EmbeddedCurvePoint;

fn main(point1: EmbeddedCurvePoint, point2: EmbeddedCurvePoint) -> pub EmbeddedCurvePoint {
    std::embedded_curve_ops::embedded_curve_add(point1, point2)
}

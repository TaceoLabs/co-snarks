use babyjubjub::BabyJubJubPoint;

fn main(x_0: Field, x_1: Field, scalar: Field) -> pub BabyJubJubPoint {
    let x = BabyJubJubPoint::new(x_0, x_1);
    x.scalar_mul(scalar)
}

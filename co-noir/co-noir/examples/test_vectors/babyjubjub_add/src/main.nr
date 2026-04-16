use babyjubjub::BabyJubJubPoint;

fn main(x_0: Field, x_1: Field) -> pub BabyJubJubPoint {
    let x = BabyJubJubPoint::new(x_0, x_1);
    let mut res = BabyJubJubPoint::identity();
    for _ in 0..256 {
        res = x.add(res);
    }
    res
}

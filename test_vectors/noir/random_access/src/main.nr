global a: [Field; 3] = [2, 3, 4];

fn main(x: Field, y: pub Field) -> pub Field {
    a[x as u32] + y
}

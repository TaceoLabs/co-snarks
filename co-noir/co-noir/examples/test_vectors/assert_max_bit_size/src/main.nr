fn main(a: Field, b: Field) -> pub Field {
    // 64, 128, 250, 252 work fine. Only fails for 253
    a.assert_max_bit_size::<253>();
    a + b
}

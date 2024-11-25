fn main(x: u64) -> pub u64 {
    approx_sigmoid(x)
}

fn approx_sigmoid(x: u64) -> u64 {
    // Follows https://github.com/data61/MP-SPDZ/blob/master/Compiler/ml.py#L110
    // [-5, -2.5, 2.5, 5]
    let cuts: [u64; 4] = [
        327680, // -5/2^-16, -327680
        163840, // -2.5/2^-16, -163840
        163840, // 163840
        327680, // 327680
    ];

    let temp = 1819 * x;
    let outputs = [
        6, // 0.0001, 0.0001 / 2^-16 = 6.5536
        temp + 9502, //0.02776 and 0.145, 0.02776 / 2^-16 = 1819.27936, 0.145/2^-16 = 9502.72
        (11141 * x) + 32768, //0.17 and 0.5, 0.17 / 2^-16 = 11141.12, 0.5/2^-16 = 32768
        temp + 56031, //0.02776 and 0.85498, 0.85498/2^-16 = 56031.96928
        65529, //0.9999 / 2^-16 = 65529.4464
    ];

    let mut index = 4; // Default to the last index in case x is above all cuts
    // Determine the correct interval index by checking against each cut
    if x <= cuts[0] {
        index = 0;
    } else if x <= cuts[1] {
        index = 1;
    } else if x <= cuts[2] {
        index = 2;
    } else if x <= cuts[3] {
        index = 3;
    }
    outputs[index]
}

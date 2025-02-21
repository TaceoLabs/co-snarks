use std::cmp::Ordering;
use std::field::bn254::decompose;
use std::ops::{Add, Mul, Sub};
fn main(x: Field, y: pub Field) -> pub Ordering {
    let new_x = Quantized::new(x);
    let new_y = Quantized::new(y);
    let zero = Quantized::zero();
    let add0 = new_x + zero;
    let sub = add0 - new_y;
    let mul = new_x * sub;
    Quantized::cmp(mul, new_y)
}

pub struct Quantized {
    // if value positive: x*scale
    // if negative: (p-x)*scale, where p is the prime of native Field (in this case from barretenberg)
    // the original value is max 60 bits, positive or negative,
    // this leaves enough space for additions and additions of single multiplications
    // 2^60-1 = 1152921504606846975
    // -1152921504606846975 <= x <= 1152921504606846975
    // -1152921504606846975/65536 <= value <= 1152921504606846975/65536
    pub x: Field,
}
pub unconstrained fn get_bytes(x: Field) -> [u8; 32] {
    x.to_be_bytes()
}

/// Check if the integer value is possitive based on the Field value used to
/// encode it.
pub fn is_positive(x: Field) -> bool {
    let (_, higher_bytes) = decompose(x);
    higher_bytes == 0
}

// check if there are bytes from 0-15, then it is negative
// This assumes the values that are multiplied have max ~60-63 bits
pub fn is_negative(x: Field) -> bool {
    let (_, higher_bytes) = decompose(x);
    higher_bytes != 0
}
impl Quantized {

    pub fn zero() -> Self {
        Quantized { x: 0 }
    }

    pub fn new(x: Field) -> Self {
        Self { x: x }
    }

    fn add(self: Self, other: Self) -> Self {
        Quantized { x: self.x + other.x } // if one is negative, this wraps around automatically
    }

    fn sub(self: Self, other: Self) -> Self {
        Quantized { x: self.x - other.x }
    }

    fn mul(self: Self, other: Self) -> Self {
        let mut temp: Field = self.x * other.x;
        let mut bytes: [u8; 32] = [0; 32];
        // Safety: get_bytes is safe
        unsafe {
            bytes = get_bytes(temp);
        }

        assert(Field::from_be_bytes::<32>(bytes) == temp);

        let negative = is_negative(temp);

        // To correctly scale down we temporary flip the sign
        if negative {
            temp = 21888242871839275222246405745257275088548364400416034343698204186575808495616
                - temp
                + 1;
            // Safety: get_bytes is safe
            unsafe {
                bytes = get_bytes(temp);
            }

            assert(Field::from_be_bytes::<32>(bytes) == temp);
        }

        // Chop off 2 bytes to scale down by 2^16 and truncate
        let mut truncated: [u8; 32] = [0; 32];
        for i in 0..30 {
            // [0, 0, am, .., a2] (chop off a0 and a1)
            truncated[i + 2] = bytes[i];
        }

        let mut new_x: Field = Field::from_be_bytes::<32>(truncated);
        // Flip back sign if the output is negative
        if negative {
            new_x = 21888242871839275222246405745257275088548364400416034343698204186575808495616
                - new_x
                + 1;
        }

        Quantized { x: new_x }
    }
}

impl Add for Quantized {
    fn add(self, other: Self) -> Self {
        self.add(other)
    }
}

impl Sub for Quantized {
    fn sub(self, other: Self) -> Self {
        self.sub(other)
    }
}

impl Mul for Quantized {
    fn mul(self, other: Self) -> Self {
        self.mul(other)
    }
}

impl Ord for Quantized { // TODO is it cheaper to create a function that returns a bool directly?
    fn cmp(self: Self, other: Self) -> Ordering {
        let self_positive = is_positive(self.x);
        let other_positive = is_positive(other.x);
        if self.x == other.x {
            Ordering::equal()
        } else if (self_positive & !other_positive) {
            Ordering::greater()
        } else if self_positive == other_positive {
            let self_smallest = self.x.lt(other.x);
            if self_smallest {
                Ordering::less()
            } else {
                Ordering::greater()
            }
        } else {
            Ordering::less()
        }
    }
}

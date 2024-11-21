use std::fmt;

use ark_ff::PrimeField;

mod plain;
mod rep3;
mod shamir;
pub use plain::PlainBrilligDriver;
pub use rep3::Rep3BrilligDriver;
pub use shamir::ShamirBrilligDriver;

pub use rep3::Rep3BrilligType;
pub use shamir::ShamirBrilligType;

pub trait BrilligDriver<F: PrimeField> {
    type BrilligType: Clone + Default + fmt::Debug + From<F> + PartialEq;
}

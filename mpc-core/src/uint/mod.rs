//! Stack-allocated fixed-width unsigned integers used as the backend for
//! binary-domain shares and ring/field interchange.

mod ruint_wrapper;

pub use ruint_wrapper::RUint;

/// A 256-bit unsigned integer.
pub type U256 = RUint<256, 4>;
/// A 320-bit unsigned integer.
pub type U320 = RUint<320, 5>;
/// A 384-bit unsigned integer.
pub type U384 = RUint<384, 6>;
/// A 512-bit unsigned integer.
pub type U512 = RUint<512, 8>;
/// A 1024-bit unsigned integer.
pub type U1024 = RUint<1024, 16>;

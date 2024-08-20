//![warn(missing_docs)]

use acvm::acir::circuit::ExpressionWidth;
pub use acvm::compiler::transform;

pub mod solver;
pub mod types;

/// The default expression width defined used by the ACVM.
pub const CO_EXPRESSION_WIDTH: ExpressionWidth = ExpressionWidth::Bounded { width: 4 };

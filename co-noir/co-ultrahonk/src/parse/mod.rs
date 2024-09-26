pub(crate) mod builder_variable;

use builder_variable::SharedBuilderVariable;
use ultrahonk::GenericUltraCircuitBuilder;

pub type CoUltraCircuitBuilder<T, P> = GenericUltraCircuitBuilder<P, SharedBuilderVariable<T, P>>;

use std::marker::PhantomData;

use ark_ec::pairing::Pairing;

use self::compiler::CodeBlock;

mod compiler;

pub struct WitnesExtension<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> WitnesExtension<P> {
    pub fn run(&self, code: CodeBlock) {}
}

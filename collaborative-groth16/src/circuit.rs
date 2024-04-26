//Copyright (c) 2021 Georgios Konstantopoulos
//
//Permission is hereby granted, free of charge, to any
//person obtaining a copy of this software and associated
//documentation files (the "Software"), to deal in the
//Software without restriction, including without
//limitation the rights to use, copy, modify, merge,
//publish, distribute, sublicense, and/or sell copies of
//the Software, and to permit persons to whom the Software
//is furnished to do so, subject to the following
//conditions:
//
//The above copyright notice and this permission notice
//shall be included in all copies or substantial portions
//of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//IN CONNECTION WITH THE SOFTWARE O THE USE OR OTHER
//DEALINGS IN THE SOFTWARE.R

//! Inspired by <https://github.com/arkworks-rs/circom-compat/blob/170b10fc9ed182b5f72ecf379033dda023d0bf07/src/circom/circuit.rs>

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use circom_types::{
    groth16::witness::Witness,
    r1cs::R1CS,
    traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
};

//TODO change my name
pub struct Circuit<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    r1cs: R1CS<P>,
    witness: Witness<P::ScalarField>,
}
impl<P: Pairing + CircomArkworksPairingBridge> Circuit<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    pub fn new(r1cs: R1CS<P>, witness: Witness<P::ScalarField>) -> Self {
        Self { r1cs, witness }
    }

    pub fn public_inputs(&self) -> Vec<P::ScalarField> {
        self.r1cs.wire_mapping[1..self.r1cs.num_inputs]
            .iter()
            .map(|i| self.witness.values[*i])
            .collect()
    }
}

impl<P: Pairing + CircomArkworksPairingBridge> ConstraintSynthesizer<P::ScalarField> for Circuit<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<P::ScalarField>,
    ) -> Result<(), SynthesisError> {
        let witness = &self.witness;
        let wire_mapping = &self.r1cs.wire_mapping;

        // Start from 1 because Arkworks implicitly allocates One for the first input
        #[allow(clippy::needless_range_loop)]
        for i in 1..self.r1cs.num_inputs {
            cs.new_input_variable(|| Ok(witness.values[wire_mapping[i]]))?;
        }

        for i in 0..self.r1cs.num_aux {
            cs.new_witness_variable(|| Ok(witness.values[wire_mapping[i + self.r1cs.num_inputs]]))?;
        }

        let make_index = |index| {
            if index < self.r1cs.num_inputs {
                Variable::Instance(index)
            } else {
                Variable::Witness(index - self.r1cs.num_inputs)
            }
        };
        let make_lc = |lc_data: &[(usize, P::ScalarField)]| {
            lc_data.iter().fold(
                LinearCombination::<P::ScalarField>::zero(),
                |lc: LinearCombination<P::ScalarField>, (index, coeff)| {
                    lc + (*coeff, make_index(*index))
                },
            )
        };

        for constraint in &self.r1cs.constraints {
            cs.enforce_constraint(
                make_lc(&constraint.0),
                make_lc(&constraint.1),
                make_lc(&constraint.2),
            )?;
        }

        Ok(())
    }
}

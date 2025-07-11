//! Evaluator
//!
//! This module contains the implementation of the evaluator for the replicated 3-party garbled circuits as described in [ABY3](https://eprint.iacr.org/2018/403.pdf). Thereby, the whole garbled circuit is buffered before given to the network.
//!
//! This file is heavily inspired by [fancy-garbling](https://github.com/GaloisInc/swanky/blob/dev/fancy-garbling/src/garble/evaluator.rs)

use super::{GCUtils, bristol_fashion::BristolFashionEvaluator, circuits::FancyBinaryConstant};
use crate::protocols::rep3::{id::PartyID, network::Rep3NetworkExt};
use fancy_garbling::{
    BinaryBundle, Fancy, FancyBinary, WireLabel, WireMod2, errors::EvaluatorError,
    util::output_tweak,
};
use mpc_net::Network;
use scuttlebutt::Block;
use sha3::{Digest, Sha3_256};

/// This struct implements the evaluator for replicated 3-party garbled circuits as described in [ABY3](https://eprint.iacr.org/2018/403.pdf).
pub struct Rep3Evaluator<'a, N: Network> {
    net: &'a N,
    current_output: usize,
    current_gate: usize,
    circuit: Vec<[u8; 16]>,
    current_circuit_element: usize,
    const_zero: Option<WireMod2>,
    const_one: Option<WireMod2>,
}

impl<'a, N: Network> Rep3Evaluator<'a, N> {
    /// Create a new evaluator.
    pub fn new(net: &'a N) -> Self {
        let id = PartyID::try_from(net.id()).expect("valid id");
        if id != PartyID::ID0 {
            panic!("Evaluator should be PartyID::ID0")
        }

        Self {
            net,
            current_output: 0,
            current_gate: 0,
            circuit: Vec::new(),
            current_circuit_element: 0,
            const_zero: None,
            const_one: None,
        }
    }

    /// Get a gate from the circuit.
    fn get_block_from_circuit(&mut self) -> eyre::Result<Block> {
        if self.current_circuit_element >= self.circuit.len() {
            eyre::bail!("Too few gates in circuits.",);
        }
        let mut block = Block::default();
        block
            .as_mut()
            .copy_from_slice(&self.circuit[self.current_circuit_element]);
        self.current_circuit_element += 1;
        Ok(block)
    }

    /// Receive the garbled circuit from the garblers.
    pub fn receive_circuit(&mut self) -> eyre::Result<()> {
        debug_assert!(self.circuit.is_empty());
        self.circuit = self.net.recv_many(PartyID::ID1)?;
        self.current_circuit_element = 0;

        let mut hasher = Sha3_256::default();
        for block in &self.circuit {
            hasher.update(block);
        }
        let is_hash = hasher.finalize();
        let should_hash: Vec<u8> = self.net.recv_from(PartyID::ID2)?;

        if should_hash != is_hash.as_slice() {
            eyre::bail!("Inconsistent Garbled Circuits: Hashes do not match!",);
        }

        Ok(())
    }

    /// The current non-free gate index of the garbling computation.
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Outputs the values to the evaluator.
    fn output_evaluator(&mut self, x: &[WireMod2]) -> eyre::Result<Vec<bool>> {
        let result = self.outputs(x).or(Err(eyre::eyre!("Output failed")))?;
        match result {
            Some(outputs) => {
                let mut res = Vec::with_capacity(outputs.len());
                for val in outputs {
                    if val >= 2 {
                        eyre::bail!("Value is not a bool");
                    }
                    res.push(val == 1);
                }
                Ok(res)
            }
            None => Err(eyre::eyre!("No output received")),
        }
    }

    /// Outputs the values to the garbler.
    fn output_garbler(&mut self, x: &[WireMod2]) -> eyre::Result<()> {
        let mut blocks = Vec::with_capacity(x.len());
        for val in x {
            let block = val.as_block();
            let mut gate = [0; 16];
            gate.copy_from_slice(block.as_ref());
            blocks.push(gate);
        }
        let (send1, send2) = rayon::join(
            || self.net.send_many(PartyID::ID1, &blocks),
            || self.net.send_many(PartyID::ID2, &blocks),
        );
        send1?;
        send2?;

        Ok(())
    }

    /// Outputs the values to the garbler with id1.
    fn output_garbler_id1(&mut self, x: &[WireMod2]) -> eyre::Result<()> {
        let mut blocks = Vec::with_capacity(x.len());
        for val in x {
            let block = val.as_block();
            let mut gate = [0; 16];
            gate.copy_from_slice(block.as_ref());
            blocks.push(gate);
        }
        self.net.send_many(PartyID::ID1, &blocks)?;

        Ok(())
    }

    /// Outputs the value to all parties
    pub fn output_all_parties(&mut self, x: &[WireMod2]) -> eyre::Result<Vec<bool>> {
        // Garbler's to evaluator
        let res = self.output_evaluator(x)?;

        // Evaluator to garbler
        self.output_garbler(x)?;

        Ok(res)
    }

    /// Outputs the value to parties ID0 and ID1
    pub fn output_to_id0_and_id1(&mut self, x: &[WireMod2]) -> eyre::Result<Vec<bool>> {
        // Garbler's to evaluator
        let res = self.output_evaluator(x)?;

        // Evaluator to garbler
        self.output_garbler_id1(x)?;

        Ok(res)
    }

    /// Read `n` `Block`s from the channel.
    #[inline(always)]
    fn read_blocks_from_circuit(&mut self, n: usize) -> eyre::Result<Vec<Block>> {
        (0..n).map(|_| self.get_block_from_circuit()).collect()
    }

    /// Read a Wire from the reader.
    pub fn read_wire_from_circuit(&mut self) -> eyre::Result<WireMod2> {
        let block = self.get_block_from_circuit()?;
        Ok(WireMod2::from_block(block, 2))
    }

    /// Receive a bundle of wires over the established channel.
    pub fn receive_bundle_from_circuit(
        &mut self,
        n: usize,
    ) -> eyre::Result<BinaryBundle<WireMod2>> {
        let mut wires = Vec::with_capacity(n);
        for _ in 0..n {
            let wire = WireMod2::from_block(self.get_block_from_circuit()?, 2);
            wires.push(wire);
        }

        Ok(BinaryBundle::new(wires))
    }

    /// Evaluates an 'and' gate given two inputs wires and two half-gates from the garbler.
    ///
    /// Outputs C = A & B
    ///
    /// Used internally as a subroutine to implement 'and' gates for `FancyBinary`.
    fn evaluate_and_gate(
        &mut self,
        a: &WireMod2,
        b: &WireMod2,
        gate0: &Block,
        gate1: &Block,
    ) -> WireMod2 {
        let gate_num = self.current_gate();
        GCUtils::evaluate_and_gate(gate_num, a, b, gate0, gate1)
    }
}

impl<N: Network> Fancy for Rep3Evaluator<'_, N> {
    type Item = WireMod2;
    type Error = EvaluatorError;

    fn constant(&mut self, _: u16, _q: u16) -> Result<WireMod2, EvaluatorError> {
        self.read_wire_from_circuit()
            .map_err(|err| EvaluatorError::CommunicationError(err.to_string()))
    }

    fn output(&mut self, x: &WireMod2) -> Result<Option<u16>, EvaluatorError> {
        let q = 2;
        let i = self.current_output();

        // Receive the output ciphertext from the garbler
        let ct = self
            .read_blocks_from_circuit(q as usize)
            .map_err(|err| EvaluatorError::CommunicationError(err.to_string()))?;

        // Attempt to brute force x using the output ciphertext
        let mut decoded = None;
        for k in 0..q {
            let hashed_wire = x.hash(output_tweak(i, k));
            if hashed_wire == ct[k as usize] {
                decoded = Some(k);
                break;
            }
        }

        if let Some(output) = decoded {
            Ok(Some(output))
        } else {
            Err(EvaluatorError::DecodingFailed)
        }
    }
}

impl<N: Network> FancyBinary for Rep3Evaluator<'_, N> {
    /// Negate is a noop for the evaluator
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(*x)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(x.plus(y))
    }

    fn and(&mut self, a: &Self::Item, b: &Self::Item) -> Result<Self::Item, Self::Error> {
        let gate0 = self
            .get_block_from_circuit()
            .map_err(|err| EvaluatorError::CommunicationError(err.to_string()))?;
        let gate1 = self
            .get_block_from_circuit()
            .map_err(|err| EvaluatorError::CommunicationError(err.to_string()))?;
        Ok(self.evaluate_and_gate(a, b, &gate0, &gate1))
    }
}

impl<N: Network> FancyBinaryConstant for Rep3Evaluator<'_, N> {
    fn const_zero(&mut self) -> Result<Self::Item, Self::Error> {
        let zero = match self.const_zero {
            Some(zero) => zero,
            None => {
                let zero = <Self as Fancy>::constant(self, 0, 2)?;
                self.const_zero = Some(zero);
                zero
            }
        };
        Ok(zero)
    }

    fn const_one(&mut self) -> Result<Self::Item, Self::Error> {
        let one = match self.const_one {
            Some(one) => one,
            None => {
                let one = <Self as Fancy>::constant(self, 1, 2)?;
                self.const_one = Some(one);
                one
            }
        };
        Ok(one)
    }
}

impl<N: Network> BristolFashionEvaluator for Rep3Evaluator<'_, N> {
    type WireValue = WireMod2;

    fn constant(
        &mut self,
        input: bool,
    ) -> Result<Self::WireValue, super::bristol_fashion::CircuitExecutionError> {
        match input {
            true => Ok(self
                .const_one()
                .map_err(|e| std::io::Error::other(format!("{e:?}")))?),
            false => Ok(self
                .const_zero()
                .map_err(|e| std::io::Error::other(format!("{e:?}")))?),
        }
    }

    fn inv(
        &mut self,
        input: &Self::WireValue,
    ) -> Result<Self::WireValue, super::bristol_fashion::CircuitExecutionError> {
        Ok(<Self as FancyBinary>::negate(self, input)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?)
    }

    fn xor(
        &mut self,
        input1: &Self::WireValue,
        input2: &Self::WireValue,
    ) -> Result<Self::WireValue, super::bristol_fashion::CircuitExecutionError> {
        Ok(<Self as FancyBinary>::xor(self, input1, input2)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?)
    }

    fn and(
        &mut self,
        input1: &Self::WireValue,
        input2: &Self::WireValue,
    ) -> Result<Self::WireValue, super::bristol_fashion::CircuitExecutionError> {
        Ok(<Self as FancyBinary>::and(self, input1, input2)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?)
    }
}

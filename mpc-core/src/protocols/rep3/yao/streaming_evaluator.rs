//! Streaming Evaluator
//!
//! This module contains the implementation of the evaluator for the replicated 3-party garbled circuits as described in [ABY3](https://eprint.iacr.org/2018/403.pdf). Thereby, the garbled gates are sent out as soon as they are prepared.
//!
//! This file is heavily inspired by [fancy-garbling](https://github.com/GaloisInc/swanky/blob/dev/fancy-garbling/src/garble/evaluator.rs)

use super::GCUtils;
use crate::protocols::rep3::{
    id::PartyID,
    network::{IoContext, Rep3Network},
    IoResult,
};
use fancy_garbling::{
    errors::EvaluatorError, util::output_tweak, BinaryBundle, Fancy, FancyBinary, WireLabel,
    WireMod2,
};
use scuttlebutt::Block;
use sha3::{Digest, Sha3_256};

/// This struct implements the evaluator for replicated 3-party garbled circuits as described in [ABY3](https://eprint.iacr.org/2018/403.pdf).
pub struct StreamingRep3Evaluator<'a, N: Rep3Network> {
    io_context: &'a mut IoContext<N>,
    current_output: usize,
    current_gate: usize,
    hash: Sha3_256, // For the ID2 to match everything sent with one hash
}

impl<'a, N: Rep3Network> StreamingRep3Evaluator<'a, N> {
    /// Create a new garbler.
    pub fn new(io_context: &'a mut IoContext<N>) -> Self {
        let id = io_context.id;
        if id != PartyID::ID0 {
            panic!("Garbler should be PartyID::ID0")
        }

        Self {
            io_context,
            current_output: 0,
            current_gate: 0,
            hash: Sha3_256::default(),
        }
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
    fn output_evaluator(&mut self, x: &[WireMod2]) -> IoResult<Vec<bool>> {
        let result = self.outputs(x).or(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Output failed",
        )))?;
        match result {
            Some(outputs) => {
                let mut res = Vec::with_capacity(outputs.len());
                for val in outputs {
                    if val >= 2 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Value is not a bool",
                        ));
                    }
                    res.push(val == 1);
                }
                Ok(res)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No output received",
            )),
        }
    }

    /// Outputs the values to the garbler.
    fn output_garbler(&mut self, x: &[WireMod2]) -> IoResult<()> {
        for val in x {
            let block = val.as_block();
            self.send_block(&block)?;
        }
        Ok(())
    }

    /// Outputs the values to the garbler with id1.
    fn output_garbler_id1(&mut self, x: &[WireMod2]) -> IoResult<()> {
        for val in x {
            let block = val.as_block();
            self.io_context.network.send(PartyID::ID1, block.as_ref())?;
        }
        Ok(())
    }

    /// Outputs the value to all parties
    pub fn output_all_parties(&mut self, x: &[WireMod2]) -> IoResult<Vec<bool>> {
        // Garbler's to evaluator
        let res = self.output_evaluator(x)?;

        // Check consistency with the second garbled circuit before releasing the result
        self.receive_hash()?;

        // Evaluator to garbler
        self.output_garbler(x)?;

        Ok(res)
    }

    /// Outputs the value to parties ID0 and ID1
    pub fn output_to_id0_and_id1(&mut self, x: &[WireMod2]) -> IoResult<Vec<bool>> {
        // Garbler's to evaluator
        let res = self.output_evaluator(x)?;

        // Check consistency with the second garbled circuit before releasing the result
        self.receive_hash()?;

        // Evaluator to garbler
        self.output_garbler_id1(x)?;

        Ok(res)
    }

    /// Receive a hash of ID2 (the second garbler) to verify the garbled circuit.
    pub fn receive_hash(&mut self) -> IoResult<()> {
        let data: Vec<u8> = self.io_context.network.recv(PartyID::ID2)?;
        let mut hash = Sha3_256::default();
        std::mem::swap(&mut hash, &mut self.hash);
        let digest = hash.finalize();
        if data != digest.as_slice() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Inconsistent Garbled Circuits: Hashes do not match!",
            ));
        }

        Ok(())
    }

    /// Send a block over the network to the garblers.
    fn send_block(&mut self, block: &Block) -> IoResult<()> {
        self.io_context.network.send(PartyID::ID1, block.as_ref())?;
        self.io_context.network.send(PartyID::ID2, block.as_ref())?;
        Ok(())
    }

    /// Receive a block from a specific party.
    fn receive_block_from(&mut self, id: PartyID) -> IoResult<Block> {
        GCUtils::receive_block_from(&mut self.io_context.network, id)
    }

    /// Send a block over the network to the evaluator.
    fn receive_block(&mut self) -> IoResult<Block> {
        let block = self.receive_block_from(PartyID::ID1)?;
        self.hash.update(block.as_ref()); // "Receive" from ID2

        Ok(block)
    }

    /// Read `n` `Block`s from the channel.
    #[inline(always)]
    fn read_blocks(&mut self, n: usize) -> IoResult<Vec<Block>> {
        (0..n).map(|_| self.receive_block()).collect()
    }

    /// Read a Wire from the reader.
    pub fn read_wire(&mut self) -> IoResult<WireMod2> {
        let block = self.receive_block()?;
        Ok(WireMod2::from_block(block, 2))
    }

    /// Receive a bundle of wires over the established channel.
    pub fn receive_bundle(&mut self, n: usize) -> IoResult<BinaryBundle<WireMod2>> {
        let mut wires = Vec::with_capacity(n);
        for _ in 0..n {
            let wire = WireMod2::from_block(self.receive_block()?, 2);
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

impl<N: Rep3Network> Fancy for StreamingRep3Evaluator<'_, N> {
    type Item = WireMod2;
    type Error = EvaluatorError;

    fn constant(&mut self, _: u16, _q: u16) -> Result<WireMod2, EvaluatorError> {
        Ok(self.read_wire()?)
    }

    fn output(&mut self, x: &WireMod2) -> Result<Option<u16>, EvaluatorError> {
        let q = 2;
        let i = self.current_output();

        // Receive the output ciphertext from the garbler
        let ct = self.read_blocks(q as usize)?;

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

impl<N: Rep3Network> FancyBinary for StreamingRep3Evaluator<'_, N> {
    /// Negate is a noop for the evaluator
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(*x)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(x.plus(y))
    }

    fn and(&mut self, a: &Self::Item, b: &Self::Item) -> Result<Self::Item, Self::Error> {
        let gate0 = self.receive_block()?;
        let gate1 = self.receive_block()?;
        Ok(self.evaluate_and_gate(a, b, &gate0, &gate1))
    }
}

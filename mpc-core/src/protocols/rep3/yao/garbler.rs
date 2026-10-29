// Parts of this file are adapted from swanky (https://github.com/GaloisInc/swanky),
// rev 5ff648457218b74da9d8323b7ca47166ff5be4b3. Copyright © 2019-2022 Galois, Inc.
// Licensed under the MIT license, see THIRD_PARTY_NOTICES in the mpc-core crate root.

//! Garbler
//!
//! This module contains the implementation of the garbler for the replicated 3-party garbled circuits as described in [ABY3](https://eprint.iacr.org/2018/403.pdf). Thereby, the whole garbled circuit is buffered before given to the network.
//!
//! This implementation is heavily inspired by [fancy-garbling](https://github.com/GaloisInc/swanky/blob/5ff648457218b74da9d8323b7ca47166ff5be4b3/fancy-garbling/src/garble/garbler.rs)

use super::fancy::{BinaryBundle, Block, Fancy, FancyBinary, GcError, WireMod2, output_tweak};
use super::{GCInputs, GCUtils, circuits::FancyBinaryConstant};
use crate::uint::FieldUint;
use crate::{
    RngType,
    protocols::rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
};
use core::panic;
use mpc_net::Network;
use rand::SeedableRng;
use sha3::{Digest, Sha3_256};

/// This struct implements the garbler for replicated 3-party garbled circuits as described in [ABY3](https://eprint.iacr.org/2018/403.pdf).
pub struct Rep3Garbler<'a, N: Network> {
    id: PartyID,
    net: &'a N,
    pub(crate) delta: WireMod2,
    current_output: usize,
    current_gate: usize,
    pub(crate) rng: RngType,
    hash: Sha3_256, // For the ID2 to match everything sent with one hash
    circuit: Vec<[u8; 16]>,
    const_zero: Option<WireMod2>,
    const_one: Option<WireMod2>,
}

impl<'a, N: Network> Rep3Garbler<'a, N> {
    /// Create a new garbler.
    pub fn new(net: &'a N, state: &mut Rep3State) -> Self {
        let mut res = Self::new_with_delta(net, state, WireMod2::default());
        res.delta = GCUtils::random_delta(&mut res.rng);
        res
    }

    /// Create a new garbler with existing delta.
    pub fn new_with_delta(net: &'a N, state: &mut Rep3State, delta: WireMod2) -> Self {
        let id = state.id;
        let seed = state.rngs.generate_garbler_randomness(state.id);
        let rng = RngType::from_seed(seed);

        Self {
            id,
            net,
            delta,
            current_output: 0,
            current_gate: 0,
            rng,
            hash: Sha3_256::default(),
            circuit: Vec::new(),
            const_zero: None,
            const_one: None,
        }
    }

    /// Add the gate to the circuit
    fn add_block_to_circuit(&mut self, block: &Block) {
        match self.id {
            PartyID::ID0 => {
                panic!("Garbler should not be PartyID::ID0");
            }
            PartyID::ID1 => {
                self.circuit.push((*block).into());
            }
            PartyID::ID2 => {
                self.hash.update(block.as_ref());
            }
        }
    }

    /// Sends the circuit to the evaluator
    pub fn send_circuit(&self) -> eyre::Result<()> {
        match self.id {
            PartyID::ID0 => {
                panic!("Garbler should not be PartyID::ID0");
            }
            PartyID::ID1 => {
                // Send the prepared circuit over the network to the evaluator
                self.net.send_many(PartyID::ID0, &self.circuit)?;
            }
            PartyID::ID2 => {
                // Send the hash of the circuit to the evaluator
                let digest = self.hash.clone().finalize();

                self.net.send_to(PartyID::ID0, digest.as_slice())?;
            }
        }
        Ok(())
    }

    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub fn encode_field<F: FieldUint>(&mut self, field: F) -> GCInputs<WireMod2> {
        GCUtils::encode_field(field, &mut self.rng, self.delta)
    }

    /// Consumes the Garbler and returns the delta.
    pub fn into_delta(self) -> WireMod2 {
        self.delta
    }

    /// The current non-free gate index of the garbling computation
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
    fn output_evaluator(&mut self, x: &[WireMod2]) -> eyre::Result<()> {
        self.outputs(x)?;
        Ok(())
    }

    /// Outputs the values to the garbler.
    fn output_garbler(&self, x: &[WireMod2]) -> eyre::Result<Vec<bool>> {
        let blocks = self.read_blocks()?;
        if blocks.len() != x.len() {
            eyre::bail!("Invalid number of blocks received");
        }

        let mut result = Vec::with_capacity(x.len());
        for (block, zero) in blocks.into_iter().zip(x.iter()) {
            if block == zero.as_block() {
                result.push(false);
            } else if block == (*zero ^ self.delta).as_block() {
                result.push(true);
            } else {
                eyre::bail!("Invalid block received",);
            }
        }
        Ok(result)
    }

    /// Outputs the value to all parties
    pub fn output_all_parties(&mut self, x: &[WireMod2]) -> eyre::Result<Vec<bool>> {
        // Garbler's to evaluator
        self.output_evaluator(x)?;

        // Check consistency with the second garbled circuit before receiving the result
        self.send_circuit()?;

        // Evaluator to garbler
        self.output_garbler(x)
    }

    /// Outputs the value to parties ID0 and ID1
    pub fn output_to_id0_and_id1(&mut self, x: &[WireMod2]) -> eyre::Result<Option<Vec<bool>>> {
        // Garbler's to evaluator
        self.output_evaluator(x)?;

        // Check consistency with the second garbled circuit before receiving the result
        self.send_circuit()?;

        // Evaluator to garbler
        if self.id == PartyID::ID1 {
            Ok(Some(self.output_garbler(x)?))
        } else {
            Ok(None)
        }
    }

    // Read `Block`s from the channel.
    #[inline(always)]
    fn read_blocks(&self) -> eyre::Result<Vec<Block>> {
        let rcv: Vec<[u8; 16]> = self.net.recv_many(PartyID::ID0)?;
        let mut result = Vec::with_capacity(rcv.len());
        for block in rcv {
            result.push(Block::from(block));
        }
        Ok(result)
    }

    /// Send a wire over the established channel.
    fn add_wire_to_circuit(&mut self, wire: &WireMod2) {
        self.add_block_to_circuit(&wire.as_block());
    }

    /// Send a bundle of wires over the established channel.
    pub fn add_bundle_to_circuit(&mut self, wires: &BinaryBundle<WireMod2>) {
        for wire in wires.wires() {
            self.add_wire_to_circuit(wire);
        }
    }

    /// Encode a wire, producing the zero wire as well as the encoded value.
    pub fn encode_wire(&mut self, val: u16) -> (WireMod2, WireMod2) {
        GCUtils::encode_wire(&mut self.rng, &self.delta, val)
    }

    /// Garbles an 'and' gate given two input wires and the delta.
    ///
    /// Outputs a tuple consisting of the two gates (that should be transferred to the evaluator)
    /// and the next wire label for the garbler.
    ///
    /// Used internally as a subroutine to implement 'and' gates for `FancyBinary`.
    fn garble_and_gate(&mut self, a: &WireMod2, b: &WireMod2) -> (Block, Block, WireMod2) {
        let gate_num = self.current_gate();
        super::fancy::garble_and_gate(gate_num, a, b, &self.delta)
    }
}

impl<N: Network> Fancy for Rep3Garbler<'_, N> {
    type Item = WireMod2;

    fn constant(&mut self, x: u16) -> Result<WireMod2, GcError> {
        let zero = WireMod2::rand(&mut self.rng);
        let wire = zero ^ self.delta.cmul(x);
        self.add_wire_to_circuit(&wire);
        Ok(zero)
    }

    fn output(&mut self, x: &WireMod2) -> Result<Option<u16>, GcError> {
        let i = self.current_output();
        let d = self.delta;
        for k in 0..2 {
            let block = (*x ^ d.cmul(k)).hash(output_tweak(i, k));
            self.add_block_to_circuit(&block);
        }
        Ok(None)
    }
}

impl<N: Network> FancyBinary for Rep3Garbler<'_, N> {
    fn and(&mut self, a: &Self::Item, b: &Self::Item) -> Result<Self::Item, GcError> {
        let (gate0, gate1, c) = self.garble_and_gate(a, b);
        self.add_block_to_circuit(&gate0);
        self.add_block_to_circuit(&gate1);
        Ok(c)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, GcError> {
        Ok(*x ^ *y)
    }

    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, GcError> {
        let delta = self.delta;
        <Self as FancyBinary>::xor(self, &delta, x)
    }
}

impl<N: Network> FancyBinaryConstant for Rep3Garbler<'_, N> {
    fn const_zero(&mut self) -> Result<Self::Item, GcError> {
        let zero = match self.const_zero {
            Some(zero) => zero,
            None => {
                let zero = <Self as Fancy>::constant(self, 0)?;
                self.const_zero = Some(zero);
                zero
            }
        };
        Ok(zero)
    }

    fn const_one(&mut self) -> Result<Self::Item, GcError> {
        // We cannot use the const_zero wire since it would leak the delta
        let zero = match self.const_one {
            Some(zero) => zero,
            None => {
                let zero = <Self as Fancy>::constant(self, 1)?;
                self.const_one = Some(zero); // The garbler stores the 0 wire
                zero
            }
        };
        Ok(zero)
    }
}

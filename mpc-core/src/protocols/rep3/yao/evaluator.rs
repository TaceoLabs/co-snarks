// This file is heavily inspired by https://github.com/GaloisInc/swanky/blob/dev/fancy-garbling/src/garble/evaluator.rs

use crate::protocols::rep3::{
    id::PartyID,
    network::{IoContext, Rep3Network},
};
use fancy_garbling::{
    errors::EvaluatorError,
    hash_wires,
    util::{output_tweak, tweak2},
    Fancy, WireLabel, WireMod2,
};
use scuttlebutt::Block;
use subtle::ConditionallySelectable;

pub(crate) struct Rep3Evaluator<'a, N: Rep3Network> {
    io_context: &'a mut IoContext<N>,
    current_output: usize,
    current_gate: usize,
}

impl<'a, N: Rep3Network> Rep3Evaluator<'a, N> {
    /// Create a new garbler.
    pub(crate) fn new(io_context: &'a mut IoContext<N>) -> Self {
        let id = io_context.id;
        if id != PartyID::ID0 {
            panic!("Garbler should be PartyID::ID0")
        }

        Self {
            io_context,
            current_output: 0,
            current_gate: 0,
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

    fn receive_block_from(&mut self, id: PartyID) -> Result<Block, EvaluatorError> {
        let data: Vec<u8> = self.io_context.network.recv(id)?;
        if data.len() != 16 {
            return Err(EvaluatorError::DecodingFailed);
        }
        let mut v = Block::default();
        v.as_mut().copy_from_slice(&data);

        Ok(v)
    }

    /// Send a block over the network to the evaluator.
    fn receive_block(&mut self) -> Result<Block, EvaluatorError> {
        let block1 = self.receive_block_from(PartyID::ID1)?;
        let block2 = self.receive_block_from(PartyID::ID2)?;

        // TODO maybe do this at separate points

        if block1 != block2 {
            return Err(EvaluatorError::CommunicationError(
                "Blocks of two garblers do not match!".to_string(),
            ));
        }

        Ok(block1)
    }

    /// Read `n` `Block`s from the channel.
    #[inline(always)]
    fn read_blocks(&mut self, n: usize) -> Result<Vec<Block>, EvaluatorError> {
        (0..n).map(|_| self.receive_block()).collect()
    }

    /// Read a Wire from the reader.
    pub fn read_wire(&mut self) -> Result<WireMod2, EvaluatorError> {
        let block = self.receive_block()?;
        Ok(WireMod2::from_block(block, 2))
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
        let g = tweak2(gate_num as u64, 0);

        let [hash_a, hash_b] = hash_wires([a, b], g);

        // garbler's half gate
        let l = WireMod2::from_block(
            Block::conditional_select(&hash_a, &(hash_a ^ *gate0), (a.color() as u8).into()),
            2,
        );

        // evaluator's half gate
        let r = WireMod2::from_block(
            Block::conditional_select(&hash_b, &(hash_b ^ *gate1), (b.color() as u8).into()),
            2,
        );

        l.plus_mov(&r.plus_mov(&a.cmul(b.color())))
    }
}

impl<'a, N: Rep3Network> Fancy for Rep3Evaluator<'a, N> {
    type Item = WireMod2;
    type Error = EvaluatorError;

    fn constant(&mut self, _: u16, _q: u16) -> Result<WireMod2, EvaluatorError> {
        self.read_wire()
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

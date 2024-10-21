use crate::{
    protocols::rep3::{
        id::PartyID,
        network::{IoContext, Rep3Network},
    },
    RngType,
};
use fancy_garbling::{
    errors::GarblerError,
    hash_wires,
    util::{output_tweak, tweak2},
    Fancy, FancyBinary, WireLabel, WireMod2,
};
use rand::SeedableRng;
use scuttlebutt::Block;
use subtle::ConditionallySelectable;

// This file is heavily inspired by https://github.com/GaloisInc/swanky/blob/dev/fancy-garbling/src/garble/garbler.rs

pub(crate) struct Rep3Garbler<'a, N: Rep3Network> {
    io_context: &'a mut IoContext<N>,
    delta: WireMod2,
    current_output: usize,
    current_gate: usize,
    rng: RngType,
}

impl<'a, N: Rep3Network> Rep3Garbler<'a, N> {
    /// Create a new garbler.
    pub(crate) fn new(io_context: &'a mut IoContext<N>) -> Self {
        let id = io_context.id;
        let seed = match id {
            PartyID::ID0 => {
                panic!("Garbler should not be PartyID::ID0")
            }
            PartyID::ID1 => io_context.rngs.rand.random_seed1(),
            PartyID::ID2 => io_context.rngs.rand.random_seed2(),
        };
        let mut rng = RngType::from_seed(seed);

        Self {
            io_context,
            delta: WireMod2::rand_delta(&mut rng, 2),
            current_output: 0,
            current_gate: 0,
            rng,
        }
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

    /// Send a block over the network to the evaluator.
    fn send_block(&mut self, block: &Block) -> Result<(), GarblerError> {
        self.io_context.network.send(PartyID::ID0, block.as_ref())?;
        Ok(())
    }

    /// Send a wire over the established channel.
    fn send_wire(&mut self, wire: &WireMod2) -> Result<(), GarblerError> {
        self.send_block(&wire.as_block())?;
        Ok(())
    }

    /// Encode a wire, producing the zero wire as well as the encoded value.
    pub fn encode_wire(&mut self, val: u16) -> (WireMod2, WireMod2) {
        let zero = WireMod2::rand(&mut self.rng, 2);
        let enc = zero.plus(&self.delta.cmul(val));
        (zero, enc)
    }

    /// Garbles an 'and' gate given two input wires and the delta.
    ///
    /// Outputs a tuple consisting of the two gates (that should be transfered to the evaluator)
    /// and the next wire label for the garbler.
    ///
    /// Used internally as a subroutine to implement 'and' gates for `FancyBinary`.
    fn garble_and_gate(
        &mut self,
        a: &WireMod2,
        b: &WireMod2,
        delta: &WireMod2,
    ) -> (Block, Block, WireMod2) {
        let q = 2;
        let d = delta;
        let gate_num = self.current_gate();

        let r = b.color(); // secret value known only to the garbler (ev knows r+b)

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = a.color(); // alpha = -A.color
        let x1 = a.plus(&d.cmul(alpha));

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (q - b.color()) % q;
        let y1 = b.plus(&d.cmul(beta));

        let ad = a.plus(d);
        let bd = b.plus(d);

        // idx is always boolean for binary gates, so it can be represented as a `u8`
        let a_selector = (a.color() as u8).into();
        let b_selector = (b.color() as u8).into();

        let b = WireMod2::conditional_select(&bd, b, b_selector);
        let new_a = WireMod2::conditional_select(&ad, a, a_selector);
        let idx = u8::conditional_select(&(r as u8), &0u8, a_selector);

        let [hash_a, hash_b, hash_x, hash_y] = hash_wires([&new_a, &b, &x1, &y1], g);

        let x = WireMod2::hash_to_mod(hash_x, q).plus_mov(&d.cmul(alpha * r % q));
        let y = WireMod2::hash_to_mod(hash_y, q);

        let gate0 =
            hash_a ^ Block::conditional_select(&x.as_block(), &x.plus(d).as_block(), idx.into());
        let gate1 = hash_b ^ y.plus(a).as_block();

        (gate0, gate1, x.plus_mov(&y))
    }
}

impl<'a, N: Rep3Network> Fancy for Rep3Garbler<'a, N> {
    type Item = WireMod2;
    type Error = GarblerError;

    fn constant(&mut self, x: u16, q: u16) -> Result<WireMod2, GarblerError> {
        let zero = WireMod2::rand(&mut self.rng, q);
        let wire = zero.plus(self.delta.cmul_eq(x));
        self.send_wire(&wire)?;
        Ok(zero)
    }

    fn output(&mut self, x: &WireMod2) -> Result<Option<u16>, GarblerError> {
        let i = self.current_output();
        let d = self.delta;
        for k in 0..2 {
            let block = x.plus(&d.cmul(k)).hash(output_tweak(i, k));
            self.send_block(&block)?;
        }
        Ok(None)
    }
}

impl<'a, N: Rep3Network> FancyBinary for Rep3Garbler<'a, N> {
    fn and(&mut self, a: &Self::Item, b: &Self::Item) -> Result<Self::Item, Self::Error> {
        let delta = self.delta;
        let (gate0, gate1, c) = self.garble_and_gate(a, b, &delta);
        self.send_block(&gate0)?;
        self.send_block(&gate1)?;
        Ok(c)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(x.plus(y))
    }

    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        let delta = self.delta;
        self.xor(&delta, x)
    }
}

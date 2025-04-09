use crate::protocols::rep3::{
    network::Rep3Network,
    yao::{streaming_garbler::StreamingRep3Garbler, GCInputs, GCUtils},
};
use fancy_garbling::WireMod2;
use mpc_types::protocols::rep3_ring::ring::{int_ring::IntRing2k, ring_impl::RingElement};

impl<N: Rep3Network> StreamingRep3Garbler<'_, N> {
    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub fn encode_ring<T: IntRing2k>(&mut self, ring: RingElement<T>) -> GCInputs<WireMod2> {
        GCUtils::encode_ring(ring, &mut self.rng, self.delta)
    }
}

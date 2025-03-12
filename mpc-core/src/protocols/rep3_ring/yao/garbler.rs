use crate::protocols::{
    rep3::yao::{garbler::Rep3Garbler, GCInputs, GCUtils},
    rep3_ring::ring::{int_ring::IntRing2k, ring_impl::RingElement},
};
use fancy_garbling::WireMod2;
use mpc_engine::Network;

impl<N: Network> Rep3Garbler<'_, N> {
    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub fn encode_ring<T: IntRing2k>(&mut self, ring: RingElement<T>) -> GCInputs<WireMod2> {
        GCUtils::encode_ring(ring, &mut self.rng, self.delta)
    }
}

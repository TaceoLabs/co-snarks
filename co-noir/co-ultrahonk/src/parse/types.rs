use crate::CoUltraCircuitBuilder;
use ark_ec::pairing::Pairing;
use mpc_core::traits::PrimeFieldMpcProtocol;

pub(crate) struct GateCounter {
    collect_gates_per_opcode: bool,
    prev_gate_count: usize,
}

impl GateCounter {
    pub(crate) fn new(collect_gates_per_opcode: bool) -> Self {
        Self {
            collect_gates_per_opcode,
            prev_gate_count: 0,
        }
    }

    pub(crate) fn compute_diff<T, P: Pairing>(
        &mut self,
        builder: &CoUltraCircuitBuilder<T, P>,
    ) -> usize
    where
        T: PrimeFieldMpcProtocol<P::ScalarField>,
    {
        if !self.collect_gates_per_opcode {
            return 0;
        }
        let new_gate_count = builder.get_num_gates();
        let diff = new_gate_count - self.prev_gate_count;
        self.prev_gate_count = new_gate_count;
        diff
    }

    pub(crate) fn track_diff<T, P: Pairing>(
        &mut self,
        builder: &CoUltraCircuitBuilder<T, P>,
        gates_per_opcode: &mut [usize],
        opcode_index: usize,
    ) where
        T: PrimeFieldMpcProtocol<P::ScalarField>,
    {
        if self.collect_gates_per_opcode {
            gates_per_opcode[opcode_index] = self.compute_diff(builder);
        }
    }
}

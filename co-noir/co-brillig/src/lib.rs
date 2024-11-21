use acir::{
    acir_field::GenericFieldElement,
    circuit::brillig::{BrilligBytecode, BrilligFunctionId, BrilligOutputs},
    AcirField as _,
};
use acvm::brillig_vm::MemoryValue;
use ark_ff::PrimeField;
use brillig::{BitSize, MemoryAddress, Opcode as BrilligOpcode};
use memory::Memory;
use mpc::BrilligDriver;

mod memory;
pub mod mpc;

pub struct CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    driver: T,
    calldata: Vec<T::BrilligType>,
    unconstrained_functions: Vec<BrilligBytecode<GenericFieldElement<F>>>,
    memory: Memory<T, F>,
    ip: usize,
}

impl<T, F> CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    pub fn run(
        &mut self,
        id: &BrilligFunctionId,
        calldata: Vec<T::BrilligType>,
        outputs: &[BrilligOutputs],
    ) -> Vec<F> {
        // reset VM for a fresh run
        // TODO this can be nicer
        self.calldata = calldata;
        self.memory = Memory::new();
        self.run_inner(id);
        todo!()
    }

    fn run_inner(&mut self, id: &BrilligFunctionId) {
        // TODO remove clone
        let opcodes = self.unconstrained_functions[id.as_usize()].bytecode.clone();
        loop {
            let opcode = &opcodes[self.ip];
            self.process_opcode(opcode);
        }
    }

    pub fn init(
        driver: T,
        unconstrained_functions: Vec<BrilligBytecode<GenericFieldElement<F>>>,
    ) -> Self {
        Self {
            driver,
            unconstrained_functions,
            calldata: vec![],
            memory: Memory::new(),
            ip: 0,
        }
    }

    fn process_opcode(&mut self, opcode: &BrilligOpcode<GenericFieldElement<F>>) {
        tracing::debug!("running opcode: {:?}", opcode);
        match opcode {
            BrilligOpcode::BinaryFieldOp {
                destination,
                op,
                lhs,
                rhs,
            } => todo!(),
            BrilligOpcode::BinaryIntOp {
                destination,
                op,
                bit_size,
                lhs,
                rhs,
            } => todo!(),
            BrilligOpcode::Not {
                destination,
                source,
                bit_size,
            } => todo!(),
            BrilligOpcode::Cast {
                destination,
                source,
                bit_size,
            } => todo!(),
            BrilligOpcode::JumpIfNot {
                condition,
                location,
            } => todo!(),
            BrilligOpcode::JumpIf {
                condition,
                location,
            } => todo!(),
            BrilligOpcode::Jump { location } => todo!(),
            BrilligOpcode::CalldataCopy {
                destination_address,
                size_address,
                offset_address,
            } => self.handle_calldata_copy(destination_address, size_address, offset_address),
            BrilligOpcode::Call { location } => todo!(),
            BrilligOpcode::Const {
                destination,
                bit_size,
                value,
            } => {
                self.handle_const(destination, bit_size, value);
            }
            BrilligOpcode::IndirectConst {
                destination_pointer,
                bit_size,
                value,
            } => todo!(),
            BrilligOpcode::Return => todo!(),
            BrilligOpcode::ForeignCall {
                function,
                destinations,
                destination_value_types,
                inputs,
                input_value_types,
            } => todo!(),
            BrilligOpcode::Mov {
                destination,
                source,
            } => self.handle_move(destination, source),
            BrilligOpcode::ConditionalMov {
                destination,
                source_a,
                source_b,
                condition,
            } => todo!(),
            BrilligOpcode::Load {
                destination,
                source_pointer,
            } => todo!(),
            BrilligOpcode::Store {
                destination_pointer,
                source,
            } => todo!(),
            BrilligOpcode::BlackBox(_) => todo!(),
            BrilligOpcode::Trap { revert_data } => todo!(),
            BrilligOpcode::Stop { return_data } => todo!(),
        }
    }
    fn increment_program_counter(&mut self) {
        self.set_program_counter(self.ip + 1)
    }

    fn set_program_counter(&mut self, value: usize) {
        //assert!(self.ip < self.opcodes.len());
        self.ip = value;
    }

    fn handle_move(&mut self, destination: &MemoryAddress, source: &MemoryAddress) {
        let source_value = self.memory.read(*source);
        self.memory.write(*destination, source_value);
        self.increment_program_counter()
    }

    fn handle_calldata_copy(
        &mut self,
        destination_address: &MemoryAddress,
        size_address: &MemoryAddress,
        offset_address: &MemoryAddress,
    ) {
        let size = self.memory.read(*size_address).to_usize();
        let offset = self.memory.read(*offset_address).to_usize();
        let values: Vec<_> = self.calldata[offset..(offset + size)]
            .iter()
            .map(|value| MemoryValue::new_field(value.clone()))
            .collect();
        self.memory.write_slice(*destination_address, &values);
        self.increment_program_counter()
    }

    fn handle_const(
        &mut self,
        destination: &MemoryAddress,
        bit_size: &BitSize,
        value: &GenericFieldElement<F>,
    ) {
        let constant = if let BitSize::Integer(bit_size) = bit_size {
            //MemoryValue::new_integer(value.to_u128(), bit_size)
            // TODO THIS IS WRONG - WE NEED THE RING IMPL ASAP
            MemoryValue::new_integer(value.to_u128(), *bit_size)
        } else {
            MemoryValue::new_field(T::BrilligType::from(value.into_repr()))
        };
        self.memory.write(*destination, constant);
        self.increment_program_counter()
    }
}

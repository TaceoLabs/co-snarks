use acir::{
    acir_field::GenericFieldElement,
    circuit::brillig::{BrilligBytecode, BrilligFunctionId, BrilligOutputs},
    AcirField as _,
};
use acvm::brillig_vm::MemoryValue;
use ark_ff::PrimeField;
use brillig::{BitSize, Label, MemoryAddress, Opcode as BrilligOpcode};
use memory::{memory_utils, Memory};
use mpc::BrilligDriver;

mod int_ops;
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
    call_stack: Vec<usize>,
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
    ) -> eyre::Result<Vec<F>> {
        // reset VM for a fresh run
        // TODO this can be nicer
        self.calldata = calldata;
        self.memory = Memory::new();
        self.run_inner(id)?;
        todo!()
    }

    fn run_inner(&mut self, id: &BrilligFunctionId) -> eyre::Result<()> {
        // TODO remove clone
        let opcodes = self.unconstrained_functions[id.as_usize()].bytecode.clone();
        loop {
            let opcode = &opcodes[self.ip];
            self.process_opcode(opcode)?;
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
            call_stack: vec![],
            memory: Memory::new(),
            ip: 0,
        }
    }

    fn process_opcode(
        &mut self,
        opcode: &BrilligOpcode<GenericFieldElement<F>>,
    ) -> eyre::Result<()> {
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
            } => self.handle_binary_int_op(destination, op, bit_size, lhs, rhs),
            BrilligOpcode::Not {
                destination,
                source,
                bit_size,
            } => todo!(),
            BrilligOpcode::Cast {
                destination,
                source,
                bit_size,
            } => self.handle_cast(destination, source, bit_size),
            BrilligOpcode::JumpIfNot {
                condition,
                location,
            } => todo!(),
            BrilligOpcode::JumpIf {
                condition,
                location,
            } => self.handle_jump_if(condition, location),
            BrilligOpcode::Jump { location } => todo!(),
            BrilligOpcode::CalldataCopy {
                destination_address,
                size_address,
                offset_address,
            } => self.handle_calldata_copy(destination_address, size_address, offset_address),
            BrilligOpcode::Call { location } => self.handle_call(location),
            BrilligOpcode::Const {
                destination,
                bit_size,
                value,
            } => self.handle_const(destination, bit_size, value),
            BrilligOpcode::IndirectConst {
                destination_pointer,
                bit_size,
                value,
            } => todo!(),
            BrilligOpcode::Return => self.handle_return(),
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

    fn handle_call(&mut self, location: &Label) -> eyre::Result<()> {
        // Push a return location
        self.call_stack.push(self.ip);
        self.set_program_counter(*location);
        Ok(())
    }

    fn handle_move(
        &mut self,
        destination: &MemoryAddress,
        source: &MemoryAddress,
    ) -> eyre::Result<()> {
        let source_value = self.memory.read(*source);
        self.memory.write(*destination, source_value);
        self.increment_program_counter();
        Ok(())
    }

    fn handle_calldata_copy(
        &mut self,
        destination_address: &MemoryAddress,
        size_address: &MemoryAddress,
        offset_address: &MemoryAddress,
    ) -> eyre::Result<()> {
        let size = self.memory.read(*size_address).to_usize();
        let offset = self.memory.read(*offset_address).to_usize();
        let values: Vec<_> = self.calldata[offset..(offset + size)]
            .iter()
            .map(|value| MemoryValue::new_field(value.clone()))
            .collect();
        self.memory.write_slice(*destination_address, &values);
        self.increment_program_counter();
        Ok(())
    }

    fn handle_const(
        &mut self,
        destination: &MemoryAddress,
        bit_size: &BitSize,
        value: &GenericFieldElement<F>,
    ) -> eyre::Result<()> {
        let constant = if let BitSize::Integer(bit_size) = bit_size {
            //MemoryValue::new_integer(value.to_u128(), bit_size)
            // TODO THIS IS WRONG - WE NEED THE RING IMPL ASAP
            MemoryValue::new_integer(value.to_u128(), *bit_size)
        } else {
            MemoryValue::new_field(T::BrilligType::from(value.into_repr()))
        };
        self.memory.write(*destination, constant);
        self.increment_program_counter();
        Ok(())
    }

    fn handle_jump_if(&mut self, condition: &MemoryAddress, location: &Label) -> eyre::Result<()> {
        // TODO UPDATE THIS AS SOON AS WE HAVE RING MPC IMPL
        // Check if condition is true
        // We use 0 to mean false and any other value to mean true
        if memory_utils::to_bool(self.memory.read(*condition))? {
            self.set_program_counter(*location);
        } else {
            self.increment_program_counter();
        }
        Ok(())
    }

    fn handle_return(&mut self) -> eyre::Result<()> {
        if let Some(return_location) = self.call_stack.pop() {
            self.set_program_counter(return_location + 1);
        } else {
            eyre::bail!("return opcode hit, but callstack already empty")
        }
        Ok(())
    }

    fn handle_cast(
        &mut self,
        destination: &MemoryAddress,
        source: &MemoryAddress,
        bit_size: &BitSize,
    ) -> eyre::Result<()> {
        let source_value = self.memory.read(*source);
        let casted_value = match (source_value, bit_size) {
            (MemoryValue::Field(_), BitSize::Field) => todo!(),
            (MemoryValue::Field(field), BitSize::Integer(bit_size)) => {
                let casted = self.driver.cast_to_int(field, *bit_size);
                MemoryValue::new_integer(casted, *bit_size)
            }
            (MemoryValue::Integer(_, _), BitSize::Field) => todo!(),
            (MemoryValue::Integer(_, _), BitSize::Integer(_)) => todo!(),
        };
        self.memory.write(*destination, casted_value);
        self.increment_program_counter();
        Ok(())
    }
}

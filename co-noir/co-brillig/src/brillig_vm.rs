use acir::{
    acir_field::GenericFieldElement,
    circuit::brillig::{BrilligBytecode, BrilligFunctionId},
};
use ark_ff::PrimeField;
use brillig::{BitSize, HeapVector, Label, MemoryAddress, Opcode as BrilligOpcode};
use memory::Memory;
use mpc::BrilligDriver;

type CoBrilligResult = (usize, usize);

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
    ) -> eyre::Result<Vec<T::BrilligType>> {
        self.calldata = calldata;
        self.ip = 0;
        let (return_data_offset, return_data_size) = self.run_inner(id)?;
        // take memory - this also resets it for next run
        let memory = std::mem::take(&mut self.memory).into_inner();
        Ok(memory[return_data_offset..return_data_offset + return_data_size].to_vec())
    }

    fn run_inner(&mut self, id: &BrilligFunctionId) -> eyre::Result<CoBrilligResult> {
        // TODO remove clone
        let opcodes = self.unconstrained_functions[id.as_usize()].bytecode.clone();
        loop {
            let opcode = &opcodes[self.ip];
            tracing::debug!("running opcode: {:?}", opcode);
            match opcode {
                BrilligOpcode::BinaryFieldOp {
                    op,
                    lhs,
                    rhs,
                    destination,
                } => self.handle_binary_field_op(*op, *lhs, *rhs, *destination)?,
                BrilligOpcode::BinaryIntOp {
                    destination,
                    op,
                    bit_size,
                    lhs,
                    rhs,
                } => self.handle_binary_int_op(*destination, *op, *bit_size, *lhs, *rhs)?,
                BrilligOpcode::Not {
                    destination: _,
                    source: _,
                    bit_size: _,
                } => todo!(),
                BrilligOpcode::Cast {
                    destination,
                    source,
                    bit_size,
                } => self.handle_cast(*destination, *source, *bit_size)?,
                BrilligOpcode::JumpIfNot {
                    condition: _,
                    location: _,
                } => todo!(),
                BrilligOpcode::JumpIf {
                    condition,
                    location,
                } => self.handle_jump_if(*condition, *location)?,

                BrilligOpcode::Jump { location } => self.handle_jump(*location)?,
                BrilligOpcode::CalldataCopy {
                    destination_address,
                    size_address,
                    offset_address,
                } => {
                    self.handle_calldata_copy(destination_address, size_address, offset_address)?
                }
                BrilligOpcode::Call { location } => self.handle_call(location)?,
                BrilligOpcode::Const {
                    destination,
                    bit_size,
                    value,
                } => self.handle_const(*destination, *bit_size, *value)?,
                BrilligOpcode::IndirectConst {
                    destination_pointer,
                    bit_size,
                    value,
                } => self.handle_indirect_const(*destination_pointer, *bit_size, *value)?,
                BrilligOpcode::Return => self.handle_return()?,
                BrilligOpcode::ForeignCall {
                    function: _,
                    destinations: _,
                    destination_value_types: _,
                    inputs: _,
                    input_value_types: _,
                } => todo!(),
                BrilligOpcode::Mov {
                    destination,
                    source,
                } => self.handle_move(destination, source)?,
                BrilligOpcode::ConditionalMov {
                    destination: _,
                    source_a: _,
                    source_b: _,
                    condition: _,
                } => todo!(),
                BrilligOpcode::Load {
                    destination,
                    source_pointer,
                } => self.handle_load(*destination, *source_pointer)?,
                BrilligOpcode::Store {
                    destination_pointer,
                    source,
                } => self.handle_store(*destination_pointer, *source)?,
                BrilligOpcode::BlackBox(blackbox_op) => self.handle_blackbox(*blackbox_op)?,
                BrilligOpcode::Trap { revert_data: _ } => todo!(),
                BrilligOpcode::Stop { return_data } => {
                    return self.handle_stop(*return_data);
                }
            }
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
        let source_value = self.memory.read(*source)?;
        self.memory.write(*destination, source_value)?;
        self.increment_program_counter();
        Ok(())
    }

    fn handle_calldata_copy(
        &mut self,
        destination_address: &MemoryAddress,
        size_address: &MemoryAddress,
        offset_address: &MemoryAddress,
    ) -> eyre::Result<()> {
        let size = self.memory.try_read_usize(*size_address)?;
        let offset = self.memory.try_read_usize(*offset_address)?;
        self.memory.write_slice(
            *destination_address,
            &self.calldata[offset..(offset + size)],
        )?;
        self.increment_program_counter();
        Ok(())
    }

    fn handle_const(
        &mut self,
        destination: MemoryAddress,
        bit_size: BitSize,
        value: GenericFieldElement<F>,
    ) -> eyre::Result<()> {
        let constant = T::constant(value.into_repr(), bit_size);
        self.memory.write(destination, constant)?;
        self.increment_program_counter();
        Ok(())
    }

    fn handle_jump_if(&mut self, condition: MemoryAddress, location: Label) -> eyre::Result<()> {
        if T::try_into_bool(self.memory.read(condition)?)? {
            self.set_program_counter(location);
        } else {
            self.increment_program_counter();
        }
        Ok(())
    }

    fn handle_jump(&mut self, location: Label) -> eyre::Result<()> {
        self.set_program_counter(location);
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
        destination: MemoryAddress,
        source: MemoryAddress,
        bit_size: BitSize,
    ) -> eyre::Result<()> {
        let source_value = self.memory.read(source)?;
        let casted_value = self.driver.cast(source_value, bit_size)?;
        self.memory.write(destination, casted_value)?;
        self.increment_program_counter();
        Ok(())
    }

    fn handle_stop(&mut self, return_data: HeapVector) -> eyre::Result<CoBrilligResult> {
        let size = self.memory.try_read_usize(return_data.size)?;
        let offset = if size > 0 {
            self.memory.read_ref(return_data.pointer)?.unwrap_direct()
        } else {
            0
        };
        Ok((offset, size))
    }

    fn handle_load(
        &mut self,
        destination: MemoryAddress,
        source_pointer: MemoryAddress,
    ) -> eyre::Result<()> {
        // Convert our source_pointer to an address
        let source = self.memory.read_ref(source_pointer)?;
        // Use our usize source index to lookup the value in memory
        let value = self.memory.read(source)?;
        self.memory.write(destination, value)?;
        self.increment_program_counter();
        Ok(())
    }

    fn handle_store(
        &mut self,
        destination_pointer: MemoryAddress,
        source: MemoryAddress,
    ) -> eyre::Result<()> {
        // Convert our destination_pointer to an address
        let destination = self.memory.read_ref(destination_pointer)?;
        // Use our usize destination index to set the value in memory
        let value = self.memory.read(source)?;
        self.memory.write(destination, value)?;
        self.increment_program_counter();
        Ok(())
    }

    fn handle_indirect_const(
        &mut self,
        destination_pointer: MemoryAddress,
        bit_size: BitSize,
        value: GenericFieldElement<F>,
    ) -> eyre::Result<()> {
        // Convert our destination_pointer to an address
        let constant = T::constant(value.into_repr(), bit_size);
        let destination = self.memory.read_ref(destination_pointer)?;
        // Use our usize destination index to set the value in memory
        self.memory.write(destination, constant)?;
        self.increment_program_counter();
        Ok(())
    }
}

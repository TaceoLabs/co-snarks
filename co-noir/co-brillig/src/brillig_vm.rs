use crate::memory::Memory;
use crate::mpc::BrilligDriver;
use acir::{
    acir_field::GenericFieldElement,
    circuit::brillig::{BrilligBytecode, BrilligFunctionId},
};
use ark_ff::PrimeField;
use brillig::{BitSize, HeapVector, Label, MemoryAddress, Opcode as BrilligOpcode};

/// The coBrillig-VM. It executes unconstrained functions for coNoir.
///
/// In contrast to Noir's Brillig-VM, we initiate one instance and reuse
/// it during the whole process. This is mostly because we need a network
/// for the MPC operations.
pub struct CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField + Clone,
{
    pub(crate) memory: Memory<T, F>,
    pub(crate) driver: T,
    pub(crate) shared_ctx: Option<T::BrilligType>,
    calldata: Vec<T::BrilligType>,
    unconstrained_functions: Vec<BrilligBytecode<GenericFieldElement<F>>>,
    call_stack: Vec<usize>,
    ip: usize,
}

/// The result of a single run of the coBrillig-VM.
///
/// **Note:** If the coBrillig-VM encountered a branch on shared
/// values, it will return sucess if one of the paths did not encounter
/// a trap. In such a case, as we do not know what the correct execution
/// path would have been, we return a success result with random noise.
/// The constructed proof will then not verify.
pub enum CoBrilligResult<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField + Clone,
{
    /// Indicates that the run of the Brillig-VM was a sucess. Holds
    /// the computed values
    Success(Vec<T::BrilligType>),
    /// Indicates that the run failed. At the moment, this only happens
    /// if we encounter a trap.
    Failed,
}

impl<T, F> CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    /// Runs the unconstrained function identified by the provided id
    /// to completion.
    ///
    /// The input to this function is the identifier (just an index to
    /// the initially provided Vec of unconstrained functions) and the
    /// field elements from the witness serving as the arguments of the
    /// unconstrained functions.
    pub fn run(
        &mut self,
        id: &BrilligFunctionId,
        calldata: Vec<T::BrilligType>,
    ) -> eyre::Result<CoBrilligResult<T, F>> {
        self.calldata = calldata;
        self.ip = 0;
        self.run_inner(id)
    }

    fn run_inner(&mut self, id: &BrilligFunctionId) -> eyre::Result<CoBrilligResult<T, F>> {
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
                } => {
                    // if we are a shared if, we get the final result here
                    if let Some(result) = self.handle_jump_if(*condition, *location, id)? {
                        return Ok(result);
                    }
                }

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
                BrilligOpcode::Trap { revert_data: _ } => break Ok(CoBrilligResult::Failed),
                BrilligOpcode::Stop { return_data } => {
                    break self.handle_stop(*return_data);
                }
            }
        }
    }

    /// Creates a new instance of the coBrillig-VM from the provided
    /// driver and a vec of unconstrained functions. This instance of
    /// the VM can only run those unconstrained functions and panics
    /// if a caller tries to call an index larger then provided
    /// by this array.
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
            shared_ctx: None,
        }
    }

    pub(crate) fn increment_program_counter(&mut self) {
        self.set_program_counter(self.ip + 1)
    }

    pub(crate) fn set_program_counter(&mut self, value: usize) {
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
        let constant = T::public_value(value.into_repr(), bit_size);
        self.memory.write(destination, constant)?;
        self.increment_program_counter();
        Ok(())
    }

    fn handle_jump_if(
        &mut self,
        address: MemoryAddress,
        location: Label,
        id: &BrilligFunctionId,
    ) -> eyre::Result<Option<CoBrilligResult<T, F>>> {
        let condition = self.memory.read(address)?;
        match T::try_into_bool(condition) {
            Ok(true) => {
                self.set_program_counter(location);
                Ok(None)
            }
            Ok(false) => {
                self.increment_program_counter();
                Ok(None)
            }
            Err(condition) => {
                if location <= self.ip {
                    eyre::bail!("can only jump forward with shared if");
                }
                if self.shared_ctx.is_some() {
                    eyre::bail!("we can only support one shared if atm");
                }
                tracing::debug!("encountered shared if - fork the universe!");
                let (mut truthy, mut falsy) = self.fork_universe(condition.clone())?;
                truthy.memory.write(address, T::public_true())?;
                truthy.set_program_counter(location);
                falsy.memory.write(address, T::public_false())?;
                falsy.increment_program_counter();

                // run both universes to the end
                let truthy_result = truthy.run_inner(id)?;
                let falsy_result = falsy.run_inner(id)?;
                let (truthy_result, falsy_result) = match (truthy_result, falsy_result) {
                    (
                        CoBrilligResult::Success(truthy_result),
                        CoBrilligResult::Success(falsy_result),
                    ) => {
                        if truthy_result.len() != falsy_result.len() {
                            eyre::bail!("truthy and falsy universe have different result lengths");
                        }
                        (truthy_result, falsy_result)
                    }
                    (CoBrilligResult::Success(truthy_result), CoBrilligResult::Failed) => {
                        tracing::debug!("falsy universe failed. We set its result to ranodm noise");
                        let falsy_result = truthy_result
                            .iter()
                            .map(|x| self.driver.random(x))
                            .collect();
                        (truthy_result, falsy_result)
                    }
                    (CoBrilligResult::Failed, CoBrilligResult::Success(falsy_result)) => {
                        tracing::debug!(
                            "truthy universe failed. We set its result to ranodm noise"
                        );
                        let truthy_result =
                            falsy_result.iter().map(|x| self.driver.random(x)).collect();
                        (truthy_result, falsy_result)
                    }
                    (CoBrilligResult::Failed, CoBrilligResult::Failed) => {
                        // both branches failed. This means we fail as well
                        tracing::debug!("both universes failed. This means we failed");
                        return Ok(Some(CoBrilligResult::Failed));
                    }
                };
                if truthy_result.len() != falsy_result.len() {
                    eyre::bail!("results from different universes have different length")
                }
                // TODO we maybe need cmux many
                let mut final_result = Vec::with_capacity(falsy_result.len());
                for (truthy, falsy) in itertools::izip!(truthy_result, falsy_result) {
                    let result = self.driver.cmux(condition.clone(), truthy, falsy)?;
                    final_result.push(result);
                }
                Ok(Some(CoBrilligResult::Success(final_result)))
            }
        }
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

    fn handle_stop(&mut self, return_data: HeapVector) -> eyre::Result<CoBrilligResult<T, F>> {
        let size = self.memory.try_read_usize(return_data.size)?;
        let offset = if size > 0 {
            self.memory.read_ref(return_data.pointer)?.unwrap_direct()
        } else {
            0
        };
        Ok(CoBrilligResult::Success(self.take_result(offset, size)))
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
        let constant = T::public_value(value.into_repr(), bit_size);
        let destination = self.memory.read_ref(destination_pointer)?;
        // Use our usize destination index to set the value in memory
        self.memory.write(destination, constant)?;
        self.increment_program_counter();
        Ok(())
    }

    fn fork_universe(&mut self, condition: T::BrilligType) -> eyre::Result<(Self, Self)> {
        let (driver1, driver2) = self.driver.fork()?;
        let (mem1, mem2) = self.memory.fork();
        let truthy_universe = Self {
            memory: mem1,
            driver: driver1,
            calldata: self.calldata.clone(),
            unconstrained_functions: self.unconstrained_functions.clone(),
            call_stack: self.call_stack.clone(),
            ip: self.ip,
            shared_ctx: Some(condition.clone()),
        };

        let falsy_universe = Self {
            memory: mem2,
            driver: driver2,
            calldata: self.calldata.clone(),
            unconstrained_functions: self.unconstrained_functions.clone(),
            call_stack: self.call_stack.clone(),
            ip: self.ip,
            shared_ctx: Some(self.driver.not(condition)?),
        };
        Ok((truthy_universe, falsy_universe))
    }

    fn take_result(&mut self, offset: usize, size: usize) -> Vec<T::BrilligType> {
        // take memory - this also resets it for next run
        let memory = std::mem::take(&mut self.memory).into_inner();
        memory[offset..offset + size].to_vec()
    }
}

use ark_ff::PrimeField;
use brillig::MemoryAddress;

use crate::mpc::BrilligDriver;

/**
*  Copied form https://github.com/noir-lang/noir/blob/68c32b4ffd9b069fe4b119327dbf4018c17ab9d4/acvm-repo/brillig_vm/src/memory.rs
*
*  We cannot use the implementation because it is bound to [AcirField]
**/

pub(super) struct Memory<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    inner: Vec<T::BrilligType>,
}

impl<T, F> Default for Memory<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    fn default() -> Self {
        Self { inner: vec![] }
    }
}

impl<T, F> Memory<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    pub(super) fn new() -> Self {
        Self { inner: vec![] }
    }

    fn get_stack_pointer(&self) -> eyre::Result<usize> {
        self.try_read_usize(MemoryAddress::Direct(0))
    }

    fn resolve(&self, address: MemoryAddress) -> eyre::Result<usize> {
        let address = match address {
            MemoryAddress::Direct(address) => address,
            MemoryAddress::Relative(offset) => self.get_stack_pointer()? + offset,
        };
        Ok(address)
    }

    /// Gets the value at address
    pub fn read(&self, address: MemoryAddress) -> eyre::Result<T::BrilligType> {
        let resolved_addr = self.resolve(address)?;
        let value = if let Some(val) = self.inner.get(resolved_addr) {
            val.clone()
        } else {
            T::BrilligType::default()
        };
        Ok(value)
    }

    pub fn try_read_usize(&self, ptr: MemoryAddress) -> eyre::Result<usize> {
        T::try_into_usize(self.read(ptr)?)
    }

    pub fn read_ref(&self, ptr: MemoryAddress) -> eyre::Result<MemoryAddress> {
        Ok(MemoryAddress::direct(self.try_read_usize(ptr)?))
    }

    pub fn read_slice(&self, addr: MemoryAddress, len: usize) -> eyre::Result<&[T::BrilligType]> {
        // Allows to read a slice of uninitialized memory if the length is zero.
        // Ideally we'd be able to read uninitialized memory in general (as read does)
        // but that's not possible if we want to return a slice instead of owned data.
        if len == 0 {
            return Ok(&[]);
        }
        let resolved_addr = self.resolve(addr)?;
        Ok(&self.inner[resolved_addr..(resolved_addr + len)])
    }

    /// Sets the value at `address` to `value`
    pub fn write(&mut self, address: MemoryAddress, value: T::BrilligType) -> eyre::Result<()> {
        let resolved_ptr = self.resolve(address)?;
        self.resize_to_fit(resolved_ptr + 1);
        self.inner[resolved_ptr] = value;
        Ok(())
    }

    fn resize_to_fit(&mut self, size: usize) {
        // Calculate new memory size
        let new_size = std::cmp::max(self.inner.len(), size);
        // Expand memory to new size with default values if needed
        self.inner.resize(new_size, T::BrilligType::default());
    }

    /// Sets the values after `address` to `values`
    pub fn write_slice(
        &mut self,
        address: MemoryAddress,
        values: &[T::BrilligType],
    ) -> eyre::Result<()> {
        let resolved_address = self.resolve(address)?;
        self.resize_to_fit(resolved_address + values.len());
        self.inner[resolved_address..(resolved_address + values.len())].clone_from_slice(values);
        Ok(())
    }

    /// Returns the values of the memory
    pub fn values(&self) -> &[T::BrilligType] {
        &self.inner
    }

    pub fn into_inner(self) -> Vec<T::BrilligType> {
        self.inner
    }
}

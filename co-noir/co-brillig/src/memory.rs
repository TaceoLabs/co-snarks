use ark_ff::PrimeField;
use brillig::{HeapArray, IntegerBitSize, MemoryAddress};

use crate::mpc::BrilligDriver;

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

    pub fn fork(&mut self) -> (Self, Self) {
        // we can take my memory
        let cloned = self.inner.clone();
        let mine = std::mem::take(&mut self.inner);
        let mem1 = Self { inner: cloned };
        let mem2 = Self { inner: mine };
        (mem1, mem2)
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

    /// Reads the memory associated with the provided heap array. We returned an owned version
    /// of the data. This differs from the original Brillig implementation's read_slice.
    pub fn read_heap_array(&self, heap_array: HeapArray) -> eyre::Result<Vec<T::BrilligType>> {
        let HeapArray { pointer, size } = heap_array;
        if size == 0 {
            return Ok(Vec::new());
        }
        let pointer = self.resolve(self.read_ref(pointer)?)?;
        let mut array = Vec::with_capacity(size);
        for offset in 0..size {
            array.push(
                self.inner
                    .get(pointer + offset)
                    .cloned()
                    .unwrap_or_default(),
            );
        }
        Ok(array)
    }

    pub fn try_read_usize(&self, ptr: MemoryAddress) -> eyre::Result<usize> {
        T::try_into_usize(self.read(ptr)?)
    }

    pub fn try_read_field(&self, ptr: MemoryAddress) -> eyre::Result<T::BrilligType> {
        T::expect_field(self.read(ptr)?)
    }

    pub fn try_read_int(
        &self,
        ptr: MemoryAddress,
        bit_size: IntegerBitSize,
    ) -> eyre::Result<T::BrilligType> {
        T::expect_int(self.read(ptr)?, bit_size)
    }

    pub fn read_ref(&self, ptr: MemoryAddress) -> eyre::Result<MemoryAddress> {
        Ok(MemoryAddress::direct(self.try_read_usize(ptr)?))
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

    pub fn into_inner(self) -> Vec<T::BrilligType> {
        self.inner
    }
}

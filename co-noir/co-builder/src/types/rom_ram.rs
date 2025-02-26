use super::field_ct::FieldCT;
use crate::builder::GenericUltraCircuitBuilder;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use mpc_core::lut::LookupTableProvider;
use num_bigint::BigUint;
use std::cmp::Ordering;
use std::ops::Index;

pub(crate) struct RomTable<F: PrimeField> {
    raw_entries: Vec<FieldCT<F>>,
    entries: Vec<FieldCT<F>>,
    length: usize,
    rom_id: usize, // Builder identifier for this ROM table
    initialized: bool,
}

impl<F: PrimeField> RomTable<F> {
    pub(crate) fn new(table_entries: Vec<FieldCT<F>>) -> Self {
        let raw_entries = table_entries;
        let length = raw_entries.len();

        // do not initialize the table yet. The input entries might all be constant,
        // if this is the case we might not have a valid pointer to a Builder
        // We get around this, by initializing the table when `operator[]` is called
        // with a non-const field element.

        Self {
            raw_entries,
            entries: Vec::new(),
            length,
            rom_id: 0,
            initialized: false,
        }
    }

    pub(crate) fn index_field_ct<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        index: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> FieldCT<F> {
        if index.is_constant() {
            let value = T::get_public(&index.get_value(builder, driver))
                .expect("Constant should be public");
            let val: BigUint = value.into();
            let val: usize = val.try_into().expect("Invalid index");
            return self[val].to_owned();
        }
        self.initialize_table(builder, driver);

        if !T::is_shared(&builder.get_variable(index.witness_index as usize)) {
            // Sanity check, only doable in plain
            let value = T::get_public(&index.get_value(builder, driver))
                .expect("Already checked it is public");
            let val: BigUint = value.into();
            assert!(val < BigUint::from(self.length));
        }

        let witness_index = index.normalize(builder, driver).get_witness_index();
        let output_idx = builder
            .read_rom_array(self.rom_id, witness_index, driver)
            .expect("Not implemented for other cases");
        FieldCT::from_witness_index(output_idx)
    }

    fn initialize_table<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        if self.initialized {
            return;
        }
        // populate table. Table entries must be normalized and cannot be constants
        for entry in self.raw_entries.iter() {
            if entry.is_constant() {
                let val = T::get_public(&entry.get_value(builder, driver))
                    .expect("Constant should be public");
                self.entries.push(FieldCT::from_witness_index(
                    builder.put_constant_variable(val),
                ));
            } else {
                self.entries.push(entry.normalize(builder, driver));
            }
        }
        self.rom_id = builder.create_rom_array(self.length);

        for i in 0..self.length {
            builder.set_rom_element(self.rom_id, i, self.entries[i].get_witness_index());
        }

        self.initialized = true;
    }
}

impl<F: PrimeField> Index<usize> for RomTable<F> {
    type Output = FieldCT<F>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

pub(crate) struct RamTable<F: PrimeField> {
    raw_entries: Vec<FieldCT<F>>,
    index_initialized: Vec<bool>,
    length: usize,
    ram_id: usize, // Builder identifier for this RAM table
    ram_table_generated_in_builder: bool,
    all_entries_written_to_with_constant_index: bool,
}

impl<F: PrimeField> RamTable<F> {
    pub(crate) fn new(table_entries: Vec<FieldCT<F>>) -> Self {
        let raw_entries = table_entries;
        let length = raw_entries.len();
        let index_initialized = vec![false; length];

        // do not initialize the table yet. The input entries might all be constant,
        // if this is the case we might not have a valid pointer to a Builder
        // We get around this, by initializing the table when `read` or `write` operator is called
        // with a non-const field element.

        Self {
            raw_entries,
            index_initialized,
            length,
            ram_id: 0,
            ram_table_generated_in_builder: false,
            all_entries_written_to_with_constant_index: false,
        }
    }

    pub(crate) fn read<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        index: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<FieldCT<F>> {
        let index_value = index.get_value(builder, driver);

        if let Some(native_index) = T::get_public(&index_value) {
            assert!(native_index < P::ScalarField::from(self.length as u64));
        }

        self.initialize_table(builder, driver)?;
        assert!(self.check_indices_initialized());

        let index_wire = if index.is_constant() {
            let nativ_index = T::get_public(&index_value).expect("Constant should be public");
            FieldCT::from_witness_index(builder.put_constant_variable(nativ_index))
        } else {
            index.to_owned()
        };

        let wit_index = index_wire.get_normalized_witness_index(builder, driver);
        let output_idx = builder.read_ram_array(self.ram_id, wit_index, driver)?;
        Ok(FieldCT::from_witness_index(output_idx))
    }

    pub(crate) fn write<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        index: &FieldCT<F>,
        value: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        let index_value = index.get_value(builder, driver);

        if let Some(native_index) = T::get_public(&index_value) {
            assert!(native_index < P::ScalarField::from(self.length as u64));
        }

        self.initialize_table(builder, driver)?;

        let index_wire = if index.is_constant() {
            let nativ_index = T::get_public(&index_value).expect("Constant should be public");
            FieldCT::from_witness_index(builder.put_constant_variable(nativ_index))
        } else {
            self.initialize_table(builder, driver)?;
            index.to_owned()
        };

        let value_value = value.get_value(builder, driver);
        let value_wire = if value.is_constant() {
            let native_wire = T::get_public(&value_value).expect("Constant should be public");
            FieldCT::from_witness_index(builder.put_constant_variable(native_wire))
        } else {
            value.to_owned()
        };

        if index.is_constant() {
            let cast_index: BigUint = T::get_public(&index_value)
                .expect("Constant should be public")
                .into();
            let cast_index = usize::try_from(cast_index).expect("Invalid index");
            if !self.index_initialized[cast_index] {
                // if index constant && not initialized
                builder.init_ram_element(
                    driver,
                    self.ram_id,
                    cast_index,
                    value_wire.get_witness_index(),
                )?;
                self.index_initialized[cast_index] = true;
                return Ok(());
            }
        }

        // else
        let index_ = index_wire.get_normalized_witness_index(builder, driver);
        let value_ = value_wire.get_normalized_witness_index(builder, driver);
        builder.write_ram_array(driver, self.ram_id, index_, value_)?;
        Ok(())
    }

    fn check_indices_initialized(&mut self) -> bool {
        if self.all_entries_written_to_with_constant_index {
            return true;
        }
        if self.length == 0 {
            return false;
        }
        let mut init = true;
        for i in self.index_initialized.iter() {
            init = init && *i;
        }
        self.all_entries_written_to_with_constant_index = init;
        self.all_entries_written_to_with_constant_index
    }

    fn initialize_table<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        if self.ram_table_generated_in_builder {
            return Ok(());
        }

        self.ram_id = builder.create_ram_array(self.length, driver);

        for (i, (raw, ind)) in self
            .raw_entries
            .iter_mut()
            .zip(self.index_initialized.iter_mut())
            .enumerate()
        {
            if *ind {
                continue;
            }
            let entry = if raw.is_constant() {
                let val = T::get_public(&raw.get_value(builder, driver))
                    .expect("Constant should be public");
                FieldCT::from_witness_index(builder.put_constant_variable(val))
            } else {
                raw.normalize(builder, driver)
            };
            builder.init_ram_element(driver, self.ram_id, i, entry.get_witness_index())?;
            *ind = true;
        }

        self.ram_table_generated_in_builder = true;
        Ok(())
    }
}

#[derive(Default, Clone)]
pub(crate) struct RomRecord<F: Clone> {
    pub(crate) index_witness: u32,
    pub(crate) value_column1_witness: u32,
    pub(crate) value_column2_witness: u32,
    pub(crate) index: F,
    pub(crate) record_witness: u32,
    pub(crate) gate_index: usize,
}

impl<F: PrimeField> RomRecord<F> {
    fn less_than(&self, other: &Self) -> bool {
        self.index < other.index
    }

    fn equal(&self, other: &Self) -> bool {
        self.index_witness == other.index_witness
            && self.value_column1_witness == other.value_column1_witness
            && self.value_column2_witness == other.value_column2_witness
            && self.index == other.index
            && self.record_witness == other.record_witness
            && self.gate_index == other.gate_index
    }
}

impl<F: PrimeField> PartialEq for RomRecord<F> {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl<F: PrimeField> Eq for RomRecord<F> {}

impl<F: PrimeField> PartialOrd for RomRecord<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: PrimeField> Ord for RomRecord<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.less_than(other) {
            Ordering::Less
        } else if self.equal(other) {
            Ordering::Equal
        } else {
            Ordering::Greater
        }
    }
}

#[derive(Default)]
pub(crate) struct RomTranscript<F: Clone> {
    // Contains the value of each index of the array
    pub(crate) state: Vec<[u32; 2]>,

    // A vector of records, each of which contains:
    // + The constant witness with the index
    // + The value in the memory slot
    // + The actual index value
    pub(crate) records: Vec<RomRecord<F>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RamAccessType {
    Read,
    Write,
}

impl Default for RamAccessType {
    fn default() -> Self {
        Self::Read
    }
}

#[derive(Clone)]
pub(crate) struct RamRecord<F: Clone> {
    pub(crate) index_witness: u32,
    pub(crate) timestamp_witness: u32,
    pub(crate) value_witness: u32,
    pub(crate) index: F,
    pub(crate) access_type: RamAccessType,
    pub(crate) timestamp: u32,
    pub(crate) record_witness: u32,
    pub(crate) gate_index: usize,
}

impl<F: Clone + Default> Default for RamRecord<F> {
    fn default() -> Self {
        Self {
            index_witness: 0,
            timestamp_witness: 0,
            value_witness: 0,
            index: F::default(),
            access_type: RamAccessType::Read,
            timestamp: 0,
            record_witness: 0,
            gate_index: 0,
        }
    }
}

impl<F: PrimeField> RamRecord<F> {
    fn less_than(&self, other: &Self) -> bool {
        let index_test = self.index < other.index;
        index_test || (self.index == other.index && self.timestamp < other.timestamp)
    }

    fn equal(&self, other: &Self) -> bool {
        self.index_witness == other.index_witness
            && self.timestamp_witness == other.timestamp_witness
            && self.value_witness == other.value_witness
            && self.index == other.index
            && self.timestamp == other.timestamp
            && self.access_type == other.access_type
            && self.record_witness == other.record_witness
            && self.gate_index == other.gate_index
    }
}

impl<F: PrimeField> PartialEq for RamRecord<F> {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl<F: PrimeField> Eq for RamRecord<F> {}

impl<F: PrimeField> PartialOrd for RamRecord<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: PrimeField> Ord for RamRecord<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.less_than(other) {
            Ordering::Less
        } else if self.equal(other) {
            Ordering::Equal
        } else {
            Ordering::Greater
        }
    }
}

#[derive(Default)]
pub(crate) struct RamTranscript<U: Clone + Default, F: PrimeField, L: LookupTableProvider<F>> {
    // Contains the value of each index of the array
    pub(crate) state: L::LutType,

    // A vector of records, each of which contains:
    // + The constant witness with the index
    // + The value in the memory slot
    // + The actual index value
    pub(crate) records: Vec<RamRecord<U>>,

    // used for RAM records, to compute the timestamp when performing a read/write
    pub(crate) access_count: usize,
}

impl<U: Clone + Default, F: PrimeField, L: LookupTableProvider<F>> RamTranscript<U, F, L> {
    pub(crate) fn from_lut(lut: L::LutType) -> Self {
        Self {
            state: lut,
            records: Vec::new(),
            access_count: 0,
        }
    }
}

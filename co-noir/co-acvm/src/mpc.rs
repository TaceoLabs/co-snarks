use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_brillig::mpc::BrilligDriver;
use mpc_core::{
    gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations},
    lut::LookupTableProvider,
};
use std::{fmt, io};

pub(super) mod plain;
pub(super) mod rep3;
pub(super) mod shamir; // Does not support everything, but basic circuits can be build using Shamir (co-builder)

/// A trait representing the MPC operations required for extending the secret-shared Noir witness in MPC.
/// The operations are generic over public and private (i.e., secret-shared) inputs.
pub trait NoirWitnessExtensionProtocol<F: PrimeField> {
    type Lookup: LookupTableProvider<F>;
    type ArithmeticShare: Clone;
    /// A type representing the values encountered during Noir compilation. It should at least contain public field elements and shared values.
    type AcvmType: Clone
        + Default
        + fmt::Debug
        + fmt::Display
        + From<Self::ArithmeticShare>
        + From<F>
        + PartialEq
        + Into<<Self::BrilligDriver as BrilligDriver<F>>::BrilligType>;
    type AcvmPoint<C: CurveGroup<BaseField = F>>: Clone + fmt::Debug + fmt::Display + From<C>;

    type BrilligDriver: BrilligDriver<F>;

    fn init_brillig_driver(&mut self) -> std::io::Result<Self::BrilligDriver>;

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<<Self::BrilligDriver as BrilligDriver<F>>::BrilligType>,
    ) -> eyre::Result<Vec<Self::AcvmType>>;

    /// Returns F::zero() as an ACVM-type. The default implementation uses the `Default` trait. If `Default` does not return 0, this function has to be overwritten.
    fn public_zero() -> Self::AcvmType {
        Self::AcvmType::default()
    }

    /// Returns the provided amount of secret-shared zeros as ACVM-types. These elements
    /// are masking element squeezed from the shared randomness, and not trivial shares.
    fn shared_zeros(&mut self, len: usize) -> io::Result<Vec<Self::AcvmType>>;

    /// Checks whether an ACVM-type is public zero.
    fn is_public_zero(a: &Self::AcvmType) -> bool;

    /// Checks whether an ACVM-type is public one.
    fn is_public_one(a: &Self::AcvmType) -> bool;

    fn cmux(
        &mut self,
        cond: Self::AcvmType,
        truthy: Self::AcvmType,
        falsy: Self::AcvmType,
    ) -> io::Result<Self::AcvmType>;

    /// Adds a public value to an ACVM-type in place: *\[target\] += public
    fn add_assign_with_public(&mut self, public: F, target: &mut Self::AcvmType);

    /// Adds to acvm types. Both can either be public or shared
    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType;

    /// Adds to acvm points. Both can either be public or shared
    fn add_points<C: CurveGroup<BaseField = F>>(
        &self,
        lhs: Self::AcvmPoint<C>,
        rhs: Self::AcvmPoint<C>,
    ) -> Self::AcvmPoint<C>;

    /// Subtracts two ACVM-type values: secret - secret
    fn sub(&mut self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType;

    /// Multiply an ACVM-types with a public value: \[c\] = public * \[secret\].
    fn mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType;

    /// Multiply two ACVM-types: \[c\] = \[secret_1\] * \[secret_2\].
    fn mul(
        &mut self,
        secret_1: Self::AcvmType,
        secret_2: Self::AcvmType,
    ) -> io::Result<Self::AcvmType>;

    /// Inverts an ACVM-type: \[c\] = \[secret\]^(-1).
    fn invert(&mut self, secret: Self::AcvmType) -> io::Result<Self::AcvmType>;

    /// Negates an ACVM-type inplace: \[a\] = -\[a\].
    fn negate_inplace(&mut self, a: &mut Self::AcvmType);

    /// Multiply an ACVM-types with a public value and add_assign with result: \[result\] += q_l * \[w_l\].
    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, result: &mut Self::AcvmType);

    fn add_assign(&mut self, lhs: &mut Self::AcvmType, rhs: Self::AcvmType);

    /// Multiply two acvm-types and a public value and stores them at target: \[*result\] = c * \[lhs\] * \[rhs\].
    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
    ) -> io::Result<Self::AcvmType>;

    /// Solves the equation \[q_l\] * w_l + \[c\] = 0, by computing \[-c\]/\[q_l\] and returning the result.
    fn solve_equation(
        &mut self,
        q_l: Self::AcvmType,
        c: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType>;

    /// Initializes a new LUT from the provided values. The index shall be the order
    /// of the values in the `Vec`. This is wrapper around the method from the [`LookupTableProvider`] as
    /// we create the table from either public or shared values.
    fn init_lut_by_acvm_type(
        &mut self,
        values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as LookupTableProvider<F>>::LutType;

    /// Wrapper around reading from a LUT by the [`Self::AcvmType`] as this can either be a
    /// public or a shared read.
    fn read_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        lut: &<Self::Lookup as LookupTableProvider<F>>::LutType,
    ) -> io::Result<Self::AcvmType>;

    /// Reads from multiple public LUTs.
    fn read_from_public_luts(
        &mut self,
        index: Self::AcvmType,
        luts: &[Vec<F>],
    ) -> io::Result<Vec<Self::AcvmType>>;

    /// Wrapper around writing a value to a LUT. The index and the value can be shared or public.
    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        lut: &mut <Self::Lookup as LookupTableProvider<F>>::LutType,
    ) -> io::Result<()>;

    /// Returns the size of a lut
    fn get_length_of_lut(lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> usize;

    /// Returns the LUT as a vector of fields if the table is public
    fn get_public_lut(
        lut: &<Self::Lookup as LookupTableProvider<F>>::LutType,
    ) -> io::Result<&Vec<F>>;

    /// Returns true if the LUT is public
    fn is_public_lut(lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> bool;

    /// Creates a shared one-hot-encoded vector from a given shared index
    fn one_hot_vector_from_shared_index(
        &mut self,
        index: Self::ArithmeticShare,
        len: usize,
    ) -> io::Result<Vec<Self::ArithmeticShare>>;

    /// Writes to a shared LUT from a given shared one-hot-encoded vector.
    fn write_to_shared_lut_from_ohv(
        &mut self,
        ohv: &[Self::ArithmeticShare],
        value: Self::ArithmeticShare,
        lut: &mut [Self::ArithmeticShare],
    ) -> io::Result<()>;

    /// Returns true if the value is shared
    fn is_shared(a: &Self::AcvmType) -> bool;

    /// Returns the share if the value is shared
    fn get_shared(a: &Self::AcvmType) -> Option<Self::ArithmeticShare>;

    /// Returns the value if the value is public
    fn get_public(a: &Self::AcvmType) -> Option<F>;

    /// Returns the value if the point is public
    fn get_public_point<C: CurveGroup<BaseField = F>>(a: &Self::AcvmPoint<C>) -> Option<C>;

    /// Checks if two shared values are equal. The result is a shared value that has value 1 if the two shared values are equal and 0 otherwise.
    fn equal(&mut self, a: &Self::AcvmType, b: &Self::AcvmType) -> std::io::Result<Self::AcvmType>;

    // TODO do we want this here?
    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> io::Result<Vec<F>>;

    /// Transforms a public value into a shared value: \[a\] = a.
    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare>;

    /// Decompose a shared value into a vector of shared values: \[a\] = a_1 + a_2 + ... + a_n. Each value a_i has at most decompose_bit_size bits, whereas the total bit size of the shares is total_bit_size_per_field. Thus, a_n, might have a smaller bitsize than the other chunks
    fn decompose_arithmetic(
        &mut self,
        input: Self::ArithmeticShare,
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>>;

    /// Decompose a shared value into a vector of shared values: \[a\] = a_1 + a_2 + ... + a_n. Each value a_i has at most decompose_bit_size bits, whereas the total bit size of the shares is total_bit_size_per_field. Thus, a_n, might have a smaller bitsize than the other chunks
    fn decompose_arithmetic_many(
        &mut self,
        input: &[Self::ArithmeticShare],
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>>;

    /// Sorts a vector of shared values in ascending order, only considering the first bitsize bits.
    /// The sort is *not* stable.
    fn sort(
        &mut self,
        inputs: &[Self::AcvmType],
        bitsize: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>>;

    /// Creates a permutation to sort a vector of shared values based on ordering key in ascending order, only considering the first bitsize bits. Then applies the permutation to the vectors in inputs.
    /// The sort *is* stable.
    fn sort_vec_by(
        &mut self,
        key: &[Self::AcvmType],
        inputs: Vec<&[Self::ArithmeticShare]>,
        bitsize: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>>;

    /// Slices a value at given indices (msb, lsb), both included in the slice.
    /// Only consideres bitsize bits.
    /// Result is thus [lo, slice, hi], where slice has all bits from lsb to msb, lo all bits smaller than lsb, and hi all bits greater msb up to bitsize.
    fn slice(
        &mut self,
        input: Self::ArithmeticShare,
        msb: u8,
        lsb: u8,
        bitsize: usize,
    ) -> std::io::Result<[Self::ArithmeticShare; 3]>;

    /// bitwise AND operation for integer datatype (i.e., the result will be smaller than a field)
    fn integer_bitwise_and(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> std::io::Result<Self::AcvmType>;

    /// bitwise XOR operation for integer datatype (i.e., the result will be smaller than a field)
    fn integer_bitwise_xor(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> std::io::Result<Self::AcvmType>;

    /// Slices input1 and input2 into a vector of basis_bits bits each, ANDs all values and rotates the results by rotation. Thereby, in total only total_bitsize bits per input are considered.
    #[expect(clippy::type_complexity)]
    fn slice_and_get_and_rotate_values(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        basis_bits: usize,
        total_bitsize: usize,
        rotation: usize,
    ) -> std::io::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )>;

    /// Slices input1 and input2 into a vector of basis_bits bits each, XORs all values and rotates the results by rotation. Thereby, in total only total_bitsize bits per input are considered.
    #[expect(clippy::type_complexity)]
    fn slice_and_get_xor_rotate_values(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        basis_bits: usize,
        total_bitsize: usize,
        rotation: usize,
    ) -> std::io::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )>;

    /// Computes the Poseidon2 permutation for the given input.
    fn poseidon2_permutation<const T: usize, const D: u64>(
        &mut self,
        input: Vec<Self::AcvmType>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<Vec<Self::AcvmType>>;

    /// Computes the matrix_multiplication in the external round of the Poseidon2 permutation for the given input.
    fn poseidon2_matmul_external_inplace<const T: usize, const D: u64>(
        &self,
        input: &mut [Self::ArithmeticShare; T],
    );

    /// Creates preprocessing data for one Poseidon2 permutation
    fn poseidon2_preprocess_permutation<const T: usize, const D: u64>(
        &mut self,
        num_poseidon: usize,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<Poseidon2Precomputations<Self::ArithmeticShare>>;

    /// Computes the external round fo the Poseidon2 permutation for the given input.
    fn poseidon2_external_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<()>;

    /// Computes the internal round fo the Poseidon2 permutation for the given input.
    fn poseidon2_internal_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<()>;

    /// Performs multi scalar multiplications.
    fn multi_scalar_mul(
        &mut self,
        points: &[Self::AcvmType],
        scalars_lo: &[Self::AcvmType],
        scalars_hi: &[Self::AcvmType],
        pedantic_solving: bool,
    ) -> std::io::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)>;

    /// Translates a share of the coordinates to a shared point
    fn field_shares_to_pointshare<C: CurveGroup<BaseField = F>>(
        &mut self,
        x: Self::AcvmType,
        y: Self::AcvmType,
        is_infinity: Self::AcvmType,
    ) -> io::Result<Self::AcvmPoint<C>>;

    /// Translates a share of the point to a share of its coordinates
    fn pointshare_to_field_shares<C: CurveGroup<BaseField = F>>(
        &mut self,
        point: Self::AcvmPoint<C>,
    ) -> std::io::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)>;

    /// Compute the greater than operation: a > b. Outputs 1 if a > b, 0 otherwise.
    fn gt(&mut self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> io::Result<Self::AcvmType>;

    /// Computes: result = if point == 0 { value } else { point }
    fn set_point_to_value_if_zero<C: CurveGroup<BaseField = F>>(
        &mut self,
        point: Self::AcvmPoint<C>,
        value: Self::AcvmPoint<C>,
    ) -> std::io::Result<Self::AcvmPoint<C>>;
}

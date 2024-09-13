use ark_ff::PrimeField;

use super::{core, network::ShamirNetwork, IoResult, ShamirProtocol};

mod ops;
pub(super) mod types;

type ShamirShare<F> = types::ShamirPrimeFieldShare<F>;

/// Performs addition between two shares.
pub fn add<F: PrimeField>(a: ShamirShare<F>, b: ShamirShare<F>) -> ShamirShare<F> {
    a + b
}

/// Performs addition between two shares where the result is stored in `a`.
pub fn add_assign<F: PrimeField>(a: &mut ShamirShare<F>, b: ShamirShare<F>) {
    *a += b;
}

/// Performs subtraction between two shares.
pub fn sub<F: PrimeField>(a: ShamirShare<F>, b: ShamirShare<F>) -> ShamirShare<F> {
    a - b
}

/// Performs subtraction between two shares where the result is stored in `a`.
pub fn sub_assign<F: PrimeField>(a: &mut ShamirShare<F>, b: ShamirShare<F>) {
    *a -= b;
}

/// Performs addition between a share and a public value.
pub fn add_public<F: PrimeField>(shared: ShamirShare<F>, public: F) -> ShamirShare<F> {
    shared + public
}

/// Performs addition between a share and a public value where the result is stored in `shared`.
pub fn add_assign_public<F: PrimeField>(shared: &mut ShamirShare<F>, public: F) {
    *shared += public;
}

/// Performs multiplication between two shares.
pub async fn mul<F: PrimeField, N: ShamirNetwork>(
    a: ShamirShare<F>,
    b: ShamirShare<F>,
    shamir: &mut ShamirProtocol<F, N>,
) -> IoResult<ShamirShare<F>> {
    let mul = a.a * b.a;
    shamir.degree_reduce(mul).await
}

/// Performs element-wise multiplication of two slices of shares.
pub async fn mul_vec<F: PrimeField, N: ShamirNetwork>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
    shamir: &mut ShamirProtocol<F, N>,
) -> std::io::Result<Vec<ShamirShare<F>>> {
    let mul = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| a.a * b.a)
        .collect::<Vec<_>>();
    shamir.degree_reduce_vec(mul).await
}

/// Performs multiplication between a share and a public value.
pub fn mul_public<F: PrimeField>(shared: ShamirShare<F>, public: F) -> ShamirShare<F> {
    shared * public
}

/// Performs multiplication between a share and a public value where the result is stored in `shared`.
pub fn mul_assign_public<F: PrimeField>(shared: &mut ShamirShare<F>, public: F) {
    *shared *= public;
}

/// Computes the inverse of a shared field element
pub async fn inv<F: PrimeField, N: ShamirNetwork>(
    a: ShamirShare<F>,
    shamir: &mut ShamirProtocol<F, N>,
) -> std::io::Result<ShamirShare<F>> {
    let r = shamir.rand().await?;
    let y = mul_open(a, r, shamir).await?;
    if y.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "During execution of inverse in MPC: cannot compute inverse of zero",
        ));
    }
    let y_inv = y.inverse().unwrap();
    Ok(r * y_inv)
}

/// Computes the inverse of a vector of shared field elements
pub async fn inv_many<F: PrimeField, N: ShamirNetwork>(
    a: &[ShamirShare<F>],
    shamir: &mut ShamirProtocol<F, N>,
) -> std::io::Result<Vec<ShamirShare<F>>> {
    todo!()
    //let r = (0..a.len())
    //    .map(|_| shamir.rand().await)
    //    .collect::<Result<Vec<_>, _>>()?;
    //let y = self.mul_open_many(a, &r)?;
    //if y.iter().any(|y| y.is_zero()) {
    //    return Err(std::io::Error::new(
    //        std::io::ErrorKind::InvalidData,
    //        "During execution of inverse in MPC: cannot compute inverse of zero",
    //    ));
    //}

    //let res = izip!(r, y).map(|(r, y)| r * y.inverse().unwrap()).collect();
    //Ok(res)
}

/// Performs negation of a share
pub fn neg<F: PrimeField>(a: ShamirShare<F>) -> ShamirShare<F> {
    -a
}

/// Opens a shared value and returns the corresponding field element.
pub async fn open<F: PrimeField, N: ShamirNetwork>(
    a: ShamirShare<F>,
    shamir: &mut ShamirProtocol<F, N>,
) -> IoResult<F> {
    let rcv = shamir
        .network
        .broadcast_next(a.a, shamir.threshold + 1)
        .await?;
    let res = core::reconstruct(&rcv, &shamir.open_lagrange_t);
    Ok(res)
}

/// Opens a vector of shared values and returns the corresponding field elements.
pub async fn open_many<F: PrimeField, N: ShamirNetwork>(
    a: &[ShamirShare<F>],
    shamir: &mut ShamirProtocol<F, N>,
) -> IoResult<Vec<F>> {
    let a_a = ShamirShare::convert_slice(a);

    let rcv = shamir
        .network
        .broadcast_next(a_a.to_owned(), shamir.threshold + 1)
        .await?;

    let mut transposed = vec![vec![F::zero(); shamir.threshold + 1]; a.len()];

    for (j, r) in rcv.into_iter().enumerate() {
        for (i, val) in r.into_iter().enumerate() {
            transposed[i][j] = val;
        }
    }

    let res = transposed
        .into_iter()
        .map(|r| core::reconstruct(&r, &shamir.open_lagrange_t))
        .collect();
    Ok(res)
}

/*
fn neg_vec_in_place(vec: &mut ShamirShare<F>Vec) {
    for a in vec.a.iter_mut() {
        a.neg_in_place();
    }
}
*/

/// Promotes a public value to a trivial share.
pub fn promote_to_trivial_share<F: PrimeField>(public_value: F) -> ShamirShare<F> {
    ShamirShare::<F>::new(public_value)
}

/// Promotes a vector of public values to trivial shares.
pub fn promote_to_trivial_shares<F: PrimeField>(public_values: &[F]) -> Vec<ShamirShare<F>> {
    public_values
        .iter()
        .copied()
        .map(promote_to_trivial_share)
        .collect()
}



/*
fn clone_from_slice(
    &self,
    dst: &mut ShamirShare<F>Vec,
    src: &ShamirShare<F>Vec,
    dst_offset: usize,
    src_offset: usize,
    len: usize,
) {
    assert!(dst.a.len() >= dst_offset + len);
    assert!(src.a.len() >= src_offset + len);
    assert!(len > 0);
    dst.a[dst_offset..dst_offset + len].clone_from_slice(&src.a[src_offset..src_offset + len]);
}
*/

/// This function performs a multiplication directly followed by an opening. This is preferred over Open(Mul(\[x\], \[y\])), since Mul performs resharing of the result for degree reduction. Thus, mul_open(\[x\], \[y\]) requires less communication in fewer rounds compared to Open(Mul(\[x\], \[y\])).
async fn mul_open<F: PrimeField, N: ShamirNetwork>(
    a: ShamirShare<F>,
    b: ShamirShare<F>,
    shamir: &mut ShamirProtocol<F, N>,
) -> std::io::Result<F> {
    let mul = a * b;
    let rcv = shamir
        .network
        .broadcast_next(mul.a, 2 * shamir.threshold + 1)
        .await?;
    Ok(core::reconstruct(&rcv, &shamir.open_lagrange_2t))
}

/// This function performs a multiplication directly followed by an opening. This is preferred over Open(Mul(\[x\], \[y\])), since Mul performs resharing of the result for degree reduction. Thus, mul_open(\[x\], \[y\]) requires less communication in fewer rounds compared to Open(Mul(\[x\], \[y\])).
pub async fn mul_open_many<F: PrimeField, N: ShamirNetwork>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
    shamir: &mut ShamirProtocol<F, N>,
) -> std::io::Result<Vec<F>> {
    let mul = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| a * b)
        .collect::<Vec<_>>();
    let mul = ShamirShare::convert_vec(mul);

    let rcv = shamir
        .network
        .broadcast_next(mul, 2 * shamir.threshold + 1)
        .await?;

    let mut transposed = vec![vec![F::zero(); 2 * shamir.threshold + 1]; a.len()];

    for (j, r) in rcv.into_iter().enumerate() {
        for (i, val) in r.into_iter().enumerate() {
            transposed[i][j] = val;
        }
    }

    let res = transposed
        .into_iter()
        .map(|r| core::reconstruct(&r, &shamir.open_lagrange_2t))
        .collect();
    Ok(res)
}

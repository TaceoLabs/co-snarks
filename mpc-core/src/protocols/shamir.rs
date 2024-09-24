use std::sync::Arc;
use tokio::sync::Mutex;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use itertools::izip;
use network::ShamirNetwork;
use rngs::ShamirRng;

use rand::{CryptoRng, Rng, SeedableRng};

use crate::RngType;

pub mod arithmetic;
pub mod core;
pub mod network;
pub mod pointshare;
mod rngs;

pub use arithmetic::types::ShamirPrimeFieldShare;
pub use pointshare::types::ShamirPointShare;

type IoResult<T> = std::io::Result<T>;
type ShamirShare<F> = ShamirPrimeFieldShare<F>;

pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
    val: F,
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Vec<ShamirShare<F>> {
    let shares = core::share(val, num_parties, degree, rng);
    ShamirShare::convert_vec_rev(shares)
}

/// Reconstructs a field element from its Shamir shares and lagrange coefficients. Thereby at least `degree` + 1 shares need to be present.
pub fn combine_field_element<F: PrimeField>(
    shares: &[ShamirShare<F>],
    coeffs: &[usize],
    degree: usize,
) -> eyre::Result<F> {
    if shares.len() != coeffs.len() {
        eyre::bail!(
            "Number of shares ({}) does not match number of party indices ({})",
            shares.len(),
            coeffs.len()
        );
    }
    if shares.len() <= degree {
        eyre::bail!(
            "Not enough shares to reconstruct the secret. Expected {}, got {}",
            degree + 1,
            shares.len()
        );
    }

    let lagrange = core::lagrange_from_coeff(&coeffs[..=degree]);
    let shares = ShamirShare::convert_slice(shares);
    let rec = core::reconstruct(&shares[..=degree], &lagrange);
    Ok(rec)
}

/// Secret shares a vector of field element using Shamir secret sharing and the provided random number generator. The field elements are split into num_parties shares each, where each party holds just one. The outputs are of type [ShamirShareVec]. The degree of the sharing polynomial (i.e., the threshold of maximum number of tolerated colluding parties) is specified by the degree parameter.
pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
    vals: &[F],
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Vec<Vec<ShamirShare<F>>> {
    let mut result = (0..num_parties)
        .map(|_| Vec::with_capacity(vals.len()))
        .collect::<Vec<_>>();

    for val in vals {
        let shares = core::share(*val, num_parties, degree, rng);
        let shares = ShamirShare::convert_vec_rev(shares);
        for (r, s) in izip!(&mut result, shares) {
            r.push(s);
        }
    }

    result
}

/// Reconstructs a vector of field elements from its Shamir shares and lagrange coefficients. The input is structured as one [ShamirShareVec] per party. Thus, shares\[i\]\[j\] represents the j-th share of party i. Thereby at least `degree` + 1 shares need to be present per field element (i.e., i > degree).
pub fn combine_field_elements<F: PrimeField>(
    shares: &[Vec<ShamirShare<F>>],
    coeffs: &[usize],
    degree: usize,
) -> eyre::Result<Vec<F>> {
    if shares.len() != coeffs.len() {
        eyre::bail!(
            "Number of shares ({}) does not match number of party indices ({})",
            shares.len(),
            coeffs.len()
        );
    }
    if shares.len() <= degree {
        eyre::bail!(
            "Not enough shares to reconstruct the secret. Expected {}, got {}",
            degree + 1,
            shares.len()
        );
    }

    let num_vals = shares[0].len();
    for share in shares.iter().skip(1) {
        if share.len() != num_vals {
            eyre::bail!(
                "Number of shares ({}) does not match number of shares in first party ({})",
                share.len(),
                num_vals
            );
        }
    }
    let mut result = Vec::with_capacity(num_vals);

    let lagrange = core::lagrange_from_coeff(&coeffs[..=degree]);

    for i in 0..num_vals {
        let s = shares
            .iter()
            .take(degree + 1)
            .map(|s| s[i].a)
            .collect::<Vec<_>>();
        let rec = core::reconstruct(&s, &lagrange);
        result.push(rec);
    }
    Ok(result)
}

/// Secret shares a curve point using Shamir secret sharing and the provided random number generator. The point is split into num_parties shares, where each party holds just one. The outputs are of type [ShamirPointShare]. The degree of the sharing polynomial (i.e., the threshold of maximum number of tolerated colluding parties) is specified by the degree parameter.
pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
    val: C,
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Vec<ShamirPointShare<C>> {
    let shares = core::share_point(val, num_parties, degree, rng);
    ShamirPointShare::convert_vec_rev(shares)
}

/// Reconstructs a curve point from its Shamir shares and lagrange coefficients. Thereby at least `degree` + 1 shares need to be present.
pub fn combine_curve_point<C: CurveGroup>(
    shares: &[ShamirPointShare<C>],
    coeffs: &[usize],
    degree: usize,
) -> eyre::Result<C> {
    if shares.len() != coeffs.len() {
        eyre::bail!(
            "Number of shares ({}) does not match number of party indices ({})",
            shares.len(),
            coeffs.len()
        );
    }
    if shares.len() <= degree {
        eyre::bail!(
            "Not enough shares to reconstruct the secret. Expected {}, got {}",
            degree + 1,
            shares.len()
        );
    }

    let lagrange = core::lagrange_from_coeff(&coeffs[..=degree]);
    let shares = ShamirPointShare::convert_slice(shares);
    let rec = core::reconstruct_point(&shares[..=degree], &lagrange);

    Ok(rec)
}

/// This struct handles the Shamir MPC protocol, including proof generation. Thus, it implements the [PrimeFieldMpcProtocol], [EcMpcProtocol], [PairingEcMpcProtocol], [FFTProvider], and [MSMProvider] traits.
pub struct ShamirProtocol<F: PrimeField, N: ShamirNetwork> {
    pub threshold: usize, // degree of the polynomial
    pub open_lagrange_t: Vec<F>,
    pub(crate) open_lagrange_2t: Vec<F>,
    mul_lagrange_2t: Vec<F>,
    // TODO
    // all forks will have a arc of the rng to get pairs
    // we should have a task that buffers pairs while the forks consume them
    // for now, when the pairs run out, the next call will block all other forks from accessing the rng and buffer more triples
    //
    // alternaitvely, all forks could have their own rng, would that be better? the rng serves a pair provider
    pub(crate) rng_buffer: Arc<Mutex<ShamirRng<F>>>,
    pub network: N,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirProtocol<F, N> {
    const KING_ID: usize = 0;

    /// Constructs the Shamir protocol from an established network. It also requires to specify the threshold t, which defines the maximum tolerated number of corrupted parties. The threshold t is thus equivalent to the degree of the sharing polynomials.
    pub fn new(threshold: usize, network: N) -> eyre::Result<Self> {
        let num_parties = network.get_num_parties();

        if 2 * threshold + 1 > num_parties {
            eyre::bail!("Threshold too large for number of parties")
        }

        let num_parties = network.get_num_parties();

        let seed: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();
        let rng_buffer = ShamirRng::new(seed, threshold, num_parties);

        // TODO fork network and spawn task that buffer pairs here?

        // We send in circles, so we need to receive from the last parties
        let id = network.get_id();
        let open_lagrange_t = core::lagrange_from_coeff(
            &(0..threshold + 1)
                .map(|i| (id + num_parties - i) % num_parties + 1)
                .collect::<Vec<_>>(),
        );
        let open_lagrange_2t = core::lagrange_from_coeff(
            &(0..2 * threshold + 1)
                .map(|i| (id + num_parties - i) % num_parties + 1)
                .collect::<Vec<_>>(),
        );

        let mul_lagrange_2t =
            core::lagrange_from_coeff(&(1..=2 * threshold + 1).collect::<Vec<_>>());

        Ok(Self {
            threshold,
            open_lagrange_t,
            open_lagrange_2t,
            mul_lagrange_2t,
            rng_buffer: Arc::new(Mutex::new(rng_buffer)),
            network,
        })
    }

    pub async fn fork(&mut self) -> std::io::Result<Self> {
        let rng_buffer = self.rng_buffer.clone();
        let network = self.network.fork().await?;
        Ok(Self {
            threshold: self.threshold,
            open_lagrange_t: self.open_lagrange_t.clone(),
            open_lagrange_2t: self.open_lagrange_2t.clone(),
            mul_lagrange_2t: self.mul_lagrange_2t.clone(),
            rng_buffer,
            network,
        })
    }

    /// This function generates and stores `amount * (threshold + 1)` doubly shared random values, which are required to evaluate the multiplication of two secret shares. Each multiplication consumes one of these preprocessed values.
    pub async fn preprocess(&mut self, amount: usize) -> std::io::Result<()> {
        self.rng_buffer
            .lock()
            .await
            .buffer_triples(&mut self.network, amount)
            .await
    }

    /// Generates a random field element and returns it as a share.
    pub async fn rand(&mut self) -> IoResult<ShamirPrimeFieldShare<F>> {
        let (r, _) = self
            .rng_buffer
            .lock()
            .await
            .get_pair(&mut self.network)
            .await?;
        Ok(ShamirPrimeFieldShare::new(r))
    }

    pub(crate) async fn degree_reduce(&mut self, mut input: F) -> std::io::Result<ShamirShare<F>> {
        let (r_t, r_2t) = self
            .rng_buffer
            .lock()
            .await
            .get_pair(&mut self.network)
            .await?;
        input += r_2t;

        let my_id = self.network.get_id();
        let my_share = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = F::zero();
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    acc += input * lagrange;
                } else {
                    let r = self.network.recv::<F>(other_id).await?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            let shares = core::share(
                acc,
                self.network.get_num_parties(),
                self.threshold,
                &mut self.rng_buffer.lock().await.rng,
            );
            let mut my_share = F::default();
            for (other_id, share) in shares.into_iter().enumerate() {
                if my_id == other_id {
                    my_share = share;
                } else {
                    self.network.send(other_id, share).await?;
                }
            }
            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send(Self::KING_ID, input).await?;
            }
            self.network.recv(Self::KING_ID).await?
        };

        Ok(ShamirShare::new(my_share - r_t))
    }

    pub(crate) async fn degree_reduce_vec(
        &mut self,
        mut inputs: Vec<F>,
    ) -> std::io::Result<Vec<ShamirShare<F>>> {
        let len = inputs.len();
        let mut r_ts = Vec::with_capacity(len);

        for inp in inputs.iter_mut() {
            let (r_t, r_2t) = self
                .rng_buffer
                .lock()
                .await
                .get_pair(&mut self.network)
                .await?;
            *inp += r_2t;
            r_ts.push(r_t);
        }

        let my_id = self.network.get_id();
        let mut my_shares = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = vec![F::zero(); len];
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    for (acc, muls) in izip!(&mut acc, &inputs) {
                        *acc += *muls * lagrange;
                    }
                } else {
                    let r = self.network.recv_many::<F>(other_id).await?;
                    if r.len() != len {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,"During execution of degree_reduce_vec in MPC: Invalid number of elements received",
                        ));
                    }
                    for (acc, muls) in izip!(&mut acc, r) {
                        *acc += muls * lagrange;
                    }
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            let mut shares = (0..self.network.get_num_parties())
                .map(|_| Vec::with_capacity(len))
                .collect::<Vec<_>>();

            for acc in acc {
                let s = core::share(
                    acc,
                    self.network.get_num_parties(),
                    self.threshold,
                    &mut self.rng_buffer.lock().await.rng,
                );
                for (des, src) in izip!(&mut shares, s) {
                    des.push(src);
                }
            }

            let mut my_share = Vec::new();
            for (other_id, share) in shares.into_iter().enumerate() {
                if my_id == other_id {
                    my_share = share;
                } else {
                    self.network.send_many(other_id, &share).await?;
                }
            }
            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send_many(Self::KING_ID, &inputs).await?;
            }
            let r = self.network.recv_many::<F>(Self::KING_ID).await?;
            if r.len() != len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,"During execution of degree_reduce_vec in MPC: Invalid number of elements received",
                ));
            }
            r
        };

        for (share, r) in izip!(&mut my_shares, r_ts) {
            *share -= r;
        }
        Ok(ShamirShare::convert_vec_rev(my_shares))
    }

    pub(crate) async fn degree_reduce_point<C>(
        &mut self,
        mut input: C,
    ) -> std::io::Result<ShamirPointShare<C>>
    where
        C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
    {
        let (r_t, r_2t) = self
            .rng_buffer
            .lock()
            .await
            .get_pair(&mut self.network)
            .await?;
        let r_t = C::generator().mul(r_t);
        let r_2t = C::generator().mul(r_2t);

        input += r_2t;
        let my_id = self.network.get_id();

        let my_share = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = C::zero();
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    acc += input * lagrange;
                } else {
                    let r = self.network.recv::<C>(other_id).await?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            let shares = core::share_point(
                acc,
                self.network.get_num_parties(),
                self.threshold,
                &mut self.rng_buffer.lock().await.rng,
            );
            let mut my_share = C::default();
            for (other_id, share) in shares.into_iter().enumerate() {
                if my_id == other_id {
                    my_share = share;
                } else {
                    self.network.send(other_id, share).await?;
                }
            }
            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send(Self::KING_ID, input).await?;
            }
            self.network.recv(Self::KING_ID).await?
        };

        Ok(ShamirPointShare::new(my_share - r_t))
    }
}

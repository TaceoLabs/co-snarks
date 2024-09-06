use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use itertools::izip;
use network::ShamirNetwork;
use pointshare::ShamirPointShare;
use rngs::ShamirRng;

use rand::{Rng, SeedableRng};

use crate::RngType;

mod core;
pub mod fieldshare;
pub mod network;
pub mod pointshare;
mod rngs;

type ShamirShare<F> = fieldshare::ShamirPrimeFieldShare<F>;

/// This struct handles the Shamir MPC protocol, including proof generation. Thus, it implements the [PrimeFieldMpcProtocol], [EcMpcProtocol], [PairingEcMpcProtocol], [FFTProvider], and [MSMProvider] traits.
pub struct ShamirProtocol<F: PrimeField, N: ShamirNetwork> {
    threshold: usize, // degree of the polynomial
    open_lagrange_t: Vec<F>,
    pub(crate) open_lagrange_2t: Vec<F>,
    mul_lagrange_2t: Vec<F>,
    rng_buffer: ShamirRng<F>,
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirProtocol<F, N> {
    const KING_ID: usize = 0;

    /// Constructs the Shamir protocol from an established network. It also requires to specify the threshold t, which defines the maximum tolerated number of corrupted parties. The threshold t is thus equivalent to the degree of the sharing polynomials.
    pub fn new(threshold: usize, network: N) -> eyre::Result<Self> {
        let num_parties = network.get_num_parties();

        if 2 * threshold + 1 > num_parties {
            eyre::bail!("Threshold too large for number of parties")
        }

        let seed: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();

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
            rng_buffer: ShamirRng::new(seed, threshold, num_parties),
            network,
            field: PhantomData,
        })
    }

    /// This function generates and stores `amount * (threshold + 1)` doubly shared random values, which are required to evaluate the multiplication of two secret shares. Each multiplication consumes one of these preprocessed values.
    pub async fn preprocess(&mut self, amount: usize) -> std::io::Result<()> {
        self.rng_buffer
            .buffer_triples(&mut self.network, amount)
            .await
    }

    pub(crate) async fn degree_reduce(&mut self, mut input: F) -> std::io::Result<ShamirShare<F>> {
        let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network).await?;
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
                &mut self.rng_buffer.rng,
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
            let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network).await?;
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
                    &mut self.rng_buffer.rng,
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
        let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network).await?;
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
                &mut self.rng_buffer.rng,
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

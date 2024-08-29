use ark_ff::PrimeField;
use itertools::izip;

use crate::traits::{LookupTableProvider, PrimeFieldMpcProtocol};

use super::{network::Rep3Network, Rep3BigUintShare, Rep3PrimeFieldShare, Rep3Protocol};

pub type MpcMap<F> = Vec<(F, F)>;

impl<F: PrimeField, N: Rep3Network> LookupTableProvider<F> for Rep3Protocol<F, N> {
    type SecretSharedSet = Vec<Rep3PrimeFieldShare<F>>;

    type SecretSharedMap = MpcMap<Rep3PrimeFieldShare<F>>;

    // Maybe give every set a dedicated ID/String to re-identify in debugging
    fn init_set(
        &self,
        values: impl IntoIterator<Item = Self::FieldShare>,
    ) -> Self::SecretSharedSet {
        tracing::debug!("initiating LUT-set");
        values.into_iter().collect()
    }

    fn contains_set(
        &mut self,
        needle: &Self::FieldShare,
        set: &Self::SecretSharedSet,
    ) -> eyre::Result<Self::FieldShare> {
        tracing::debug!("checking if value is in set of size {}", set.len());
        //first get a vector of true/false
        let equals_vec = set
            .iter()
            .map(|ele| self.equals_bit(needle, ele))
            .collect::<eyre::Result<Vec<_>>>()?;
        tracing::debug!("got binary equals vec now or tree..");
        //or tree to get result
        self.or_tree(equals_vec)
    }

    fn init_map(
        &self,
        values: impl IntoIterator<Item = (Self::FieldShare, Self::FieldShare)>,
    ) -> Self::SecretSharedMap {
        tracing::debug!("initiating LUT-map");
        values.into_iter().collect()
    }

    fn get_from_lut(
        &mut self,
        needle: &Self::FieldShare,
        map: &Self::SecretSharedMap,
    ) -> eyre::Result<Self::FieldShare> {
        // make some experiments which is faster
        // a single for each or multiple chained iterators...
        //
        //first iterate over keys and perform equality check
        tracing::debug!("doing read on LUT-map of size {}", map.len());
        tracing::debug!("get random zeros for blinding..");
        let mut zeros_a = Vec::with_capacity(map.len());
        zeros_a.resize_with(map.len(), || {
            // this impl cannot fail
            let (a, b) = self.rngs.rand.random_fes::<F>();
            a - b
        });
        self.network.send_next_many(&zeros_a)?;
        let zeros_b = self.network.recv_prev_many::<F>()?;
        tracing::debug!("now perform equals and cmux...");
        let mut result = Rep3PrimeFieldShare::default();
        for ((key, map), zero_a, zero_b) in
            izip!(map.iter(), zeros_a.into_iter(), zeros_b.into_iter())
        {
            // this is super slow - we can batch it?
            let zero_share = Rep3PrimeFieldShare::new(zero_a, zero_b);
            let equals = self.equals(needle, key)?;
            let cmux = self.cmux(&equals, map, &zero_share)?;
            result = self.add(&result, &cmux);
        }
        tracing::debug!("got a result!");
        Ok(result)
    }

    fn write_to_lut(
        &mut self,
        needle: Self::FieldShare,
        value: Self::FieldShare,
        map: &mut Self::SecretSharedMap,
    ) -> eyre::Result<()> {
        tracing::debug!("doing write on LUT-map of size {}", map.len());
        // we do not need any zeros here
        for (key, map) in map.iter_mut() {
            // this is super slow - we can batch it?
            let equals = self.equals(&needle, key)?;
            let cmux = self.cmux(&equals, &value, map)?;
            *map = cmux;
        }
        tracing::debug!("we are done");
        Ok(())
    }
}

impl<F: PrimeField, N: Rep3Network> Rep3Protocol<F, N> {
    fn single_or(
        &mut self,
        lhs: Rep3BigUintShare,
        rhs: Rep3BigUintShare,
    ) -> eyre::Result<Rep3BigUintShare> {
        let mut xor = &lhs ^ &rhs;
        let and = self.and(lhs, rhs, F::MODULUS_BIT_SIZE as usize)?;
        xor ^= &and;
        Ok(xor)
    }
    fn or_tree(
        &mut self,
        mut inputs: Vec<Rep3BigUintShare>,
    ) -> eyre::Result<Rep3PrimeFieldShare<F>> {
        let mut num = inputs.len();

        tracing::debug!("starting or tree over {} elements", inputs.len());
        while num > 1 {
            tracing::trace!("binary tree still has {} elements", num);
            let mod_ = num & 1;
            num >>= 1;

            let (a_vec, tmp) = inputs.split_at(num);
            let (b_vec, leftover) = tmp.split_at(num);

            //this is super slow as it is not batched. For now this is ok, but not for the future
            let mut res = a_vec
                .iter()
                .zip(b_vec)
                .map(|(a, b)| self.single_or(a.clone(), b.clone()))
                .collect::<eyre::Result<Vec<_>>>()?;

            res.extend_from_slice(leftover);
            inputs = res;

            num += mod_;
        }
        let bin_result = inputs[0].clone();
        tracing::debug!("got binary result - now b2a..");
        let result = self.b2a(bin_result)?;
        tracing::debug!("we did it!");
        Ok(result)
    }
}

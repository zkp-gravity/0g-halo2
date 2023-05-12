use ff::PrimeField;
use halo2_proofs::{circuit::{Layouter, AssignedCell}, plonk::Error};

mod array_lookup;
mod bit_selector;
mod byte_selector;
pub mod single_bit_bloom_filter;

pub(crate) trait BloomFilterInstructions<F: PrimeField> {
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<AssignedCell<F, F>, Error>;
}

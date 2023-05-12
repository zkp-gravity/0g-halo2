use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};

use self::{
    array_lookup::{
        ArrayLookupChip, ArrayLookupChipConfig, ArrayLookupConfig, ArrayLookupInstructions,
    },
    bit_selector::{BitSelectorChip, BitSelectorChipConfig, BitSelectorInstructions},
    byte_selector::{ByteSelectorChip, ByteSelectorChipConfig, ByteSelectorInstructions},
};

mod array_lookup;
mod bit_selector;
mod byte_selector;
pub mod single_bit_bloom_filter;

#[derive(Debug, Clone)]
pub(crate) struct BloomFilterConfig {
    /// Number of hashes per bloom filter
    pub(crate) n_hashes: usize,

    /// Number of bits per hash, i.e., the log2 of the number of bits in the bloom filter array
    pub(crate) bits_per_hash: usize,
}

pub(crate) trait BloomFilterInstructions<F: PrimeField> {
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub(crate) struct BloomFilterChipConfig {
    array_lookup_config: ArrayLookupChipConfig,
    byte_selector_config: ByteSelectorChipConfig,
    bit_selector_config: BitSelectorChipConfig,
}

pub(crate) struct BloomFilterChip<F: PrimeField> {
    config: BloomFilterChipConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> BloomFilterChip<F> {
    pub fn construct(config: BloomFilterChipConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_columns: [Column<Advice>; 6],
        bloom_filter_config: BloomFilterConfig,
    ) -> BloomFilterChipConfig {
        // word_index_bits trades off the number of advice rows and the number of table rows:
        // - The number of advice rows is roughly 2^word_index_bits
        // - The number of table rows is roughly 2^(bits_per_hash - word_index_bits - 3)
        // Ideally, we'll want to balance the two, but since we'll need more advice rows
        // for other things, we should prioritize fewer advice rows.
        let word_index_bits = (bloom_filter_config.bits_per_hash - 3) / 2;

        let array_lookup_config = ArrayLookupConfig {
            n_hashes: bloom_filter_config.n_hashes,
            bits_per_hash: bloom_filter_config.bits_per_hash,
            word_index_bits,
        };

        let array_lookup_config = ArrayLookupChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            advice_columns[4],
            array_lookup_config,
        );
        let bit_selector_config = BitSelectorChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
        );
        let byte_selector_config = ByteSelectorChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            advice_columns[4],
            advice_columns[5],
            // Reuse byte column of bit selector chip
            bit_selector_config.byte_column,
        );

        BloomFilterChipConfig {
            array_lookup_config,
            byte_selector_config,
            bit_selector_config,
        }
    }
}

impl<F: PrimeField> BloomFilterInstructions<F> for BloomFilterChip<F> {
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        let array_lookup_chip = ArrayLookupChip::construct(self.config.array_lookup_config.clone());
        let byte_selector_chip =
            ByteSelectorChip::<F>::construct(self.config.byte_selector_config.clone());
        let bit_selector_chip =
            BitSelectorChip::<F>::construct(self.config.bit_selector_config.clone());

        let lookup_results = array_lookup_chip.bloom_lookup(layouter, hash_value, bloom_index)?;

        let mut bits = vec![];
        for lookup_result in lookup_results {
            let byte = byte_selector_chip.select_byte(
                layouter,
                lookup_result.word,
                lookup_result.byte_index,
                array_lookup_chip.bytes_per_word(),
            )?;
            let bit = bit_selector_chip.select_bit(layouter, byte, lookup_result.bit_index)?;
            bits.push(bit);
        }

        todo!()
    }
}

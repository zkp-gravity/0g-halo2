//! A collection of gadgets that implement a bloom filter.
//!
//! There are two options:
//! - [`single_bit_bloom_filter`]: This module implements a simple gadgets where
//!   individual bits are stored in the lookup table. This can lead to very large
//!  lookup tables and few advice rows.
//! - [`BloomFilterChip`]: This gadget implements a more complex approach, where
//!   the lookup table stores larger words which are decomposed into bytes and bits.
//!   A hyperparameter trades off the number of advice rows and the number of table rows,
//!   which is set automatically such that the two are roughly equal.
//!
//! Both gadgets implement the [`BloomFilterInstructions`] trait and can be used interchangibly.
use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, TableColumn},
};
use ndarray::Array2;

pub use self::{
    and_bits::{AndBitsChip, AndBitsChipConfig, AndBitsInstruction},
    array_lookup::{
        ArrayLookupChip, ArrayLookupChipConfig, ArrayLookupConfig, ArrayLookupInstructions,
    },
    bit_selector::{BitSelectorChip, BitSelectorChipConfig, BitSelectorInstructions},
    byte_selector::{ByteSelectorChip, ByteSelectorChipConfig, ByteSelectorInstructions},
};

pub mod and_bits;
pub mod array_lookup;
pub mod bit_selector;
pub mod byte_selector;
pub mod single_bit_bloom_filter;

/// Configuration of the bloom filter.
#[derive(Debug, Clone)]
pub struct BloomFilterConfig {
    /// Number of hashes per bloom filter
    pub n_hashes: usize,

    /// Number of bits per hash, i.e., the log2 of the number of bits in the bloom filter array
    pub bits_per_hash: usize,
}

/// The interface of the bloom filter gadget.
pub trait BloomFilterInstructions<F: PrimeFieldBits> {
    /// Performs a bloom filter lookup, given a hash value.
    /// The hash value is interpreted as a `bits_per_hash * n_hashes`-bit integer
    /// and split into `n_hashes` words of `bits_per_hash` bits each.
    /// For each sub hash, it performs an array lookup and ands together the corresponding
    /// bits.
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub struct BloomFilterChipConfig {
    array_lookup_config: ArrayLookupChipConfig,
    byte_selector_config: ByteSelectorChipConfig,
    bit_selector_config: BitSelectorChipConfig,
    and_bits_config: AndBitsChipConfig,

    // A column of all bytes (not unique). Public so that it can be reused by other gadgets.
    pub byte_column: TableColumn,
}

/// Implements a bloom filter lookup using a 3-way lookup strategy.
///
/// Each index is interpreted as a word index, a byte index and a bit index.
/// For each lookup, the following steps are performed:
/// 1. The [`ArrayLookupChip`] is used to decompose the index
///    and look up the word, using a table lookup.
/// 2. The [`ByteSelectorChip`] is used to select the byte.
/// 3. The [`BitSelectorChip`] is used to select the bit using a table
///    lookup.
/// 4. The [`AndBitsChip`] is used to and together the bits.
pub struct BloomFilterChip<F: PrimeFieldBits> {
    array_lookup_chip: ArrayLookupChip<F>,
    byte_selector_chip: ByteSelectorChip<F>,
    bit_selector_chip: BitSelectorChip<F>,
    and_bits_chip: AndBitsChip<F>,
}

impl<F: PrimeFieldBits> BloomFilterChip<F> {
    /// Constructs a new bloom filter chip.
    pub fn construct(config: BloomFilterChipConfig, bloom_filter_arrays: Array2<bool>) -> Self {
        let array_lookup_chip =
            ArrayLookupChip::construct(config.array_lookup_config.clone(), &bloom_filter_arrays);
        let byte_selector_chip =
            ByteSelectorChip::<F>::construct(config.byte_selector_config.clone());
        let bit_selector_chip = BitSelectorChip::<F>::construct(config.bit_selector_config.clone());
        let and_bits_chip = AndBitsChip::<F>::construct(config.and_bits_config.clone());

        Self {
            array_lookup_chip,
            byte_selector_chip,
            bit_selector_chip,
            and_bits_chip,
        }
    }

    /// Loads all lookup tables.
    /// Should be called once before [`BloomFilterInstructions::bloom_lookup`]!
    pub fn load(&mut self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.array_lookup_chip.load(layouter)?;

        // The byte selector reuses the bytes table of the bit selector,
        // so nothing else to be loaded here.
        self.bit_selector_chip.load(layouter)?;

        Ok(())
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_columns: [Column<Advice>; 6],
        bloom_filter_config: BloomFilterConfig,
    ) -> BloomFilterChipConfig {
        let array_lookup_config = ArrayLookupChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            advice_columns[4],
            bloom_filter_config.into(),
        );
        let bit_selector_config = BitSelectorChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
        );

        // Reuse byte column of bit selector chip
        let byte_column = bit_selector_config.byte_column;

        let byte_selector_config = ByteSelectorChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            advice_columns[4],
            advice_columns[5],
            byte_column,
        );
        let and_bits_config = AndBitsChip::configure(meta, advice_columns[4], advice_columns[5]);

        BloomFilterChipConfig {
            array_lookup_config,
            byte_selector_config,
            bit_selector_config,
            and_bits_config,
            byte_column,
        }
    }
}

impl<F: PrimeFieldBits> BloomFilterInstructions<F> for BloomFilterChip<F> {
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        let lookup_results =
            self.array_lookup_chip
                .array_lookup(layouter, hash_value, bloom_index)?;

        let mut bits = vec![];
        for lookup_result in lookup_results {
            let byte = self.byte_selector_chip.select_byte(
                layouter,
                lookup_result.word,
                lookup_result.byte_index,
                self.array_lookup_chip.bytes_per_word(),
            )?;
            let bit = self
                .bit_selector_chip
                .select_bit(layouter, byte, lookup_result.bit_index)?;
            bits.push(bit);
        }
        let result = self.and_bits_chip.and_bits(layouter, bits)?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ff::PrimeFieldBits;
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, Instance},
    };
    use ndarray::Array2;

    use super::{
        BloomFilterChip, BloomFilterChipConfig, BloomFilterConfig, BloomFilterInstructions,
    };

    #[derive(Default)]
    struct MyCircuit<F: PrimeFieldBits> {
        input: u64,
        bloom_index: u64,
        bloom_filter_arrays: Array2<bool>,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct Config {
        bloom_filter_chip_config: BloomFilterChipConfig,
        advice_columns: [Column<Advice>; 6],
        instance: Column<Instance>,
    }

    impl<F: PrimeFieldBits> Circuit<F> for MyCircuit<F> {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let instance = meta.instance_column();

            let advice_columns = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];

            for advice in advice_columns {
                meta.enable_equality(advice);
            }
            meta.enable_equality(instance);

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let bloom_filter_config = BloomFilterConfig {
                n_hashes: 2,
                bits_per_hash: 10,
            };
            let bloom_filter_chip_config =
                BloomFilterChip::configure(meta, advice_columns, bloom_filter_config);

            Config {
                bloom_filter_chip_config,
                advice_columns,
                instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let input_cell = layouter.assign_region(
                || "input",
                |mut region| {
                    region.assign_advice(
                        || "input",
                        config.advice_columns[0],
                        0,
                        || Value::known(F::from(self.input)),
                    )
                },
            )?;

            let mut bloom_filter_chip = BloomFilterChip::construct(
                config.bloom_filter_chip_config,
                self.bloom_filter_arrays.clone(),
            );
            bloom_filter_chip.load(&mut layouter)?;

            let hash_value = bloom_filter_chip.bloom_lookup(
                &mut layouter.namespace(|| "bloom_filter_lookup"),
                input_cell,
                F::from(self.bloom_index),
            )?;

            layouter.constrain_instance(hash_value.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    #[test]
    fn test_all_positive() {
        let k = 14;
        let bloom_filter_arrays = Array2::<u8>::ones((1, 1024)).mapv(|_| true);
        let circuit = MyCircuit::<Fp> {
            input: 8,
            bloom_index: 0,
            bloom_filter_arrays,
            _marker: PhantomData,
        };
        let output = Fp::from(1);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_all_negative() {
        let k = 14;
        let bloom_filter_arrays = Array2::<u8>::ones((1, 1024)).mapv(|_| false);
        let circuit = MyCircuit::<Fp> {
            input: 8,
            bloom_index: 0,
            bloom_filter_arrays,
            _marker: PhantomData,
        };
        let output = Fp::from(0);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_index_1_2_positive() {
        let k = 14;
        let mut bloom_filter_arrays = Array2::<u8>::ones((1, 1024)).mapv(|_| false);
        bloom_filter_arrays[[0, 1]] = true;
        bloom_filter_arrays[[0, 2]] = true;
        let circuit = MyCircuit::<Fp> {
            input: 0b0000000001_0000000010,
            bloom_index: 0,
            bloom_filter_arrays,
            _marker: PhantomData,
        };
        let output = Fp::from(1);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_index_1_2_negative() {
        let k = 14;
        let mut bloom_filter_arrays = Array2::<u8>::ones((1, 1024)).mapv(|_| false);
        bloom_filter_arrays[[0, 0]] = true;
        bloom_filter_arrays[[0, 2]] = true;
        let circuit = MyCircuit::<Fp> {
            input: 0b0000000001_0000000010,
            bloom_index: 0,
            bloom_filter_arrays,
            _marker: PhantomData,
        };
        let output = Fp::from(0);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn plot() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("bloom-filter-layout.png", (1024, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Bloom filter Layout", ("sans-serif", 60))
            .unwrap();

        let bloom_filter_arrays = Array2::<u8>::ones((1, 1024)).mapv(|_| true);
        let circuit = MyCircuit::<Fp> {
            input: 2,
            bloom_index: 0,
            bloom_filter_arrays,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(6, &circuit, &root)
            .unwrap();
    }
}

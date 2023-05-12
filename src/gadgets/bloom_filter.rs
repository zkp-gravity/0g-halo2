use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use ndarray::Array2;

use self::{
    and_bits::{AndBitsChip, AndBitsChipConfig, AndBitsInstruction},
    array_lookup::{
        ArrayLookupChip, ArrayLookupChipConfig, ArrayLookupConfig, ArrayLookupInstructions,
    },
    bit_selector::{BitSelectorChip, BitSelectorChipConfig, BitSelectorInstructions},
    byte_selector::{ByteSelectorChip, ByteSelectorChipConfig, ByteSelectorInstructions},
};

mod and_bits;
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
    and_bits_config: AndBitsChipConfig,
}

pub(crate) struct BloomFilterChip<F: PrimeField> {
    config: BloomFilterChipConfig,
    bloom_filter_arrays: Array2<bool>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> BloomFilterChip<F> {
    pub fn construct(config: BloomFilterChipConfig, bloom_filter_arrays: Array2<bool>) -> Self {
        Self {
            config,
            bloom_filter_arrays,
            _marker: PhantomData,
        }
    }

    pub(crate) fn load(&mut self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let mut array_lookup_chip = ArrayLookupChip::construct(
            self.config.array_lookup_config.clone(),
            self.bloom_filter_arrays.clone(),
        );
        array_lookup_chip.load(layouter)?;

        // The byte selector reuses the bytes table of the bit selector,
        // so nothing else to be loaded here.
        let mut bit_selector_chip =
            BitSelectorChip::<F>::construct(self.config.bit_selector_config.clone());
        bit_selector_chip.load(layouter)?;

        Ok(())
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_columns: [Column<Advice>; 6],
        bloom_filter_config: BloomFilterConfig,
    ) -> BloomFilterChipConfig {
        // word_index_bits trades off the number of advice rows and the number of table rows.
        // For each bloom filter, we have:
        // - The number of advice rows is roughly n_hashes * 2^byte_index_bits for the byte lookup
        // - The number of table rows is roughly 2^(bits_per_hash - byte_index_bits - 3)
        // Ideally, we'll want to balance the two, but since we'll need more advice rows
        // for other things, we should prioritize fewer advice rows.
        let byte_index_bits = ((bloom_filter_config.bits_per_hash as f32 - 3.0) / 2.0
            - (bloom_filter_config.n_hashes as f32).log2().floor())
            as usize;
        let word_bits = byte_index_bits + 3;
        let word_index_bits = bloom_filter_config.bits_per_hash - word_bits;
        println!(
            "Using words of {} bits with a byte address of {} bits!",
            word_bits, word_index_bits
        );

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
        let and_bits_config = AndBitsChip::configure(meta, advice_columns[4], advice_columns[5]);

        BloomFilterChipConfig {
            array_lookup_config,
            byte_selector_config,
            bit_selector_config,
            and_bits_config,
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
        let array_lookup_chip = ArrayLookupChip::construct(
            self.config.array_lookup_config.clone(),
            self.bloom_filter_arrays.clone(),
        );
        let byte_selector_chip =
            ByteSelectorChip::<F>::construct(self.config.byte_selector_config.clone());
        let bit_selector_chip =
            BitSelectorChip::<F>::construct(self.config.bit_selector_config.clone());
        let and_bits_chip = AndBitsChip::<F>::construct(self.config.and_bits_config.clone());

        let lookup_results = array_lookup_chip.array_lookup(layouter, hash_value, bloom_index)?;

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
        let result = and_bits_chip.and_bits(layouter, bits)?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ff::PrimeField;
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
    struct MyCircuit<F: PrimeField> {
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

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
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

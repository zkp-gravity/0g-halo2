use std::marker::PhantomData;

use crate::utils::{decompose_word, to_u32};
use ff::PrimeField;
/// Gadget that implements the bloom filter lookup:
///
/// Given the `bloom_input`, `bloom_index`, `class_index` inputs, it:
/// - Hashes `bloom_input` to get the `l`-bit hash
/// - Decomposes the hash into `n_lookup` indices of length `l / n_lookup`
/// - Performs a table lookup for each index
/// - Returns 1 iff. all indices led to a positive lookup
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector, TableColumn},
    poly::Rotation,
};
use ndarray::Array2;

pub(crate) trait BloomFilterInstructions<F: PrimeField> {
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub(crate) struct BloomFilterConfig {
    /// Number of hashes per bloom filter
    pub(crate) n_hashes: usize,

    pub(crate) bits_per_hash: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct BloomFilterChipConfig {
    hashes: Column<Advice>,
    hash_accumulator: Column<Advice>,
    bloom_index: Column<Advice>,
    bloom_value: Column<Advice>,
    bloom_accumulator: Column<Advice>,

    validate_hash_accumulators_selector: Selector,
    hash_equality_selector: Selector,
    bloom_filter_lookup_selector: Selector,
    validate_bloom_accumulators_selector: Selector,

    table_bloom_index: TableColumn,
    table_bloom_value: TableColumn,

    bloom_filter_config: BloomFilterConfig,
}

pub(crate) struct BloomFilterChip<F: PrimeField> {
    config: BloomFilterChipConfig,
    bloom_filter_arrays: Option<Array2<bool>>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> BloomFilterChip<F> {
    pub(crate) fn construct(config: BloomFilterChipConfig) -> Self {
        BloomFilterChip {
            config,
            // Set to known initially, have to call load() before synthesis
            bloom_filter_arrays: None,
            _marker: PhantomData,
        }
    }

    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        hashes: Column<Advice>,
        hash_accumulator: Column<Advice>,
        bloom_index: Column<Advice>,
        bloom_value: Column<Advice>,
        bloom_accumulator: Column<Advice>,
        bloom_filter_config: BloomFilterConfig,
    ) -> BloomFilterChipConfig {
        assert!(bloom_filter_config.bits_per_hash < 64);

        let validate_hash_accumulators_selector = meta.selector();
        meta.create_gate("validate_hash_accumulators", |meta| {
            let selector = meta.query_selector(validate_hash_accumulators_selector);

            let hash = meta.query_advice(hashes, Rotation::cur());
            let acc_cur = meta.query_advice(hash_accumulator, Rotation::cur());
            let acc_next = meta.query_advice(hash_accumulator, Rotation::next());

            let shift_multiplier = F::from(1 << bloom_filter_config.bits_per_hash);
            Constraints::with_selector(selector, vec![acc_cur * shift_multiplier + hash - acc_next])
        });

        let hash_equality_selector = meta.selector();
        meta.create_gate("hash_equality", |meta| {
            let selector = meta.query_selector(hash_equality_selector);

            let hash = meta.query_advice(hashes, Rotation::cur());
            let hash_acc = meta.query_advice(hash_accumulator, Rotation::cur());

            Constraints::with_selector(selector, vec![hash_acc - hash])
        });

        let table_bloom_index = meta.lookup_table_column();
        let table_bloom_value = meta.lookup_table_column();
        let bloom_filter_lookup_selector = meta.complex_selector();
        meta.lookup("bloom filter lookup", |meta| {
            let selector = meta.query_selector(bloom_filter_lookup_selector);

            let bloom_index = meta.query_advice(bloom_index, Rotation::cur());
            let bloom_value = meta.query_advice(bloom_value, Rotation::cur());

            // TODO: Handle selector=0 case
            vec![
                (selector.clone() * bloom_index, table_bloom_index),
                (selector * bloom_value, table_bloom_value),
            ]
        });

        let validate_bloom_accumulators_selector = meta.selector();
        meta.create_gate("validate_bloom_accumulators", |meta| {
            let selector = meta.query_selector(validate_bloom_accumulators_selector);

            let bloom_value = meta.query_advice(bloom_value, Rotation::cur());
            let acc_cur = meta.query_advice(bloom_accumulator, Rotation::cur());
            let acc_next = meta.query_advice(bloom_accumulator, Rotation::next());

            Constraints::with_selector(selector, vec![acc_cur * bloom_value - acc_next])
        });

        BloomFilterChipConfig {
            // Advice Columns
            hashes,
            hash_accumulator,
            bloom_index,
            bloom_value,
            bloom_accumulator,

            // Selectors
            validate_hash_accumulators_selector,
            hash_equality_selector,
            bloom_filter_lookup_selector,
            validate_bloom_accumulators_selector,

            // Table Columns
            table_bloom_index,
            table_bloom_value,

            bloom_filter_config,
        }
    }

    pub(crate) fn load(
        &mut self,
        layouter: &mut impl Layouter<F>,
        bloom_filter_arrays: Array2<bool>,
    ) -> Result<(), Error> {
        let bloom_filter_length = 1 << self.config.bloom_filter_config.bits_per_hash;
        assert_eq!(bloom_filter_arrays.shape()[1], bloom_filter_length);

        layouter.assign_table(
            || "bloom_filters",
            |mut table| {
                let mut offset = 0usize;

                for bloom_index in 0..bloom_filter_arrays.shape()[0] {
                    for i in 0..bloom_filter_length {
                        let bloom_value = bloom_filter_arrays[(bloom_index, i)];
                        let bloom_value = if bloom_value { F::ONE } else { F::ZERO };
                        let bloom_value = Value::known(bloom_value);

                        table.assign_cell(
                            || "bloom_index",
                            self.config.table_bloom_index,
                            offset,
                            || Value::known(F::from(bloom_index as u64)),
                        )?;

                        table.assign_cell(
                            || "bloom_value",
                            self.config.table_bloom_value,
                            offset,
                            || bloom_value,
                        )?;

                        offset += 1;
                    }
                }

                Ok(())
            },
        )?;

        self.bloom_filter_arrays = Some(bloom_filter_arrays);
        Ok(())
    }
}

impl<F: PrimeField> BloomFilterInstructions<F> for BloomFilterChip<F> {
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "look up hash values",
            |mut region| {
                let n_hashes = self.config.bloom_filter_config.n_hashes;
                let bloom_filter_arrays = self
                    .bloom_filter_arrays
                    .as_ref()
                    .expect("Should call load() before bloom_lookup()!");

                // Compute values to put in cells
                let hash_values = hash_value.value().map(|hash_value| {
                    let mut words = decompose_word(
                        hash_value,
                        self.config.bloom_filter_config.n_hashes,
                        self.config.bloom_filter_config.bits_per_hash,
                    );
                    // Accumulator has to start with most significant word
                    // Otherwise, the order doesn't matter, because a all results ANDed together anyway.
                    words.reverse();
                    words
                });
                let shift_multiplier = F::from(1 << self.config.bloom_filter_config.bits_per_hash);
                let hash_accumulators = hash_values
                    .clone()
                    .map(|hash_values| {
                        let mut accumulators: Vec<F> = vec![F::ZERO];
                        for (i, hash_value) in hash_values.iter().enumerate() {
                            accumulators.push(accumulators[i] * shift_multiplier + hash_value);
                        }
                        accumulators
                    })
                    .transpose_vec(n_hashes + 1);
                let bloom_values = hash_values.clone().map(|hash_values| {
                    let bloom_index = to_u32(&bloom_index) as usize;
                    let bloom_values: Vec<F> = hash_values
                        .iter()
                        .map(|i| {
                            let bloom_value =
                                bloom_filter_arrays[(bloom_index, to_u32(i) as usize)];
                            if bloom_value {
                                F::ONE
                            } else {
                                F::ZERO
                            }
                        })
                        .collect();
                    bloom_values
                });
                let bloom_accumulators = bloom_values
                    .clone()
                    .map(|bloom_values| {
                        let mut accumulators: Vec<F> = vec![F::ONE];
                        for (i, bloom_value) in bloom_values.iter().enumerate() {
                            accumulators.push(accumulators[i] * bloom_value);
                        }
                        accumulators
                    })
                    .transpose_vec(n_hashes + 1);
                let hash_values = hash_values.transpose_vec(n_hashes);
                let bloom_values = bloom_values.transpose_vec(n_hashes);

                // Assign hash values
                // print_value("Hash value", hash_value.value());
                // print_values("Hash values", &hash_values);
                for (i, hash_value) in hash_values.iter().enumerate() {
                    region.assign_advice(
                        || format!("hash_value_{i}"),
                        self.config.hashes,
                        i,
                        || *hash_value,
                    )?;
                }
                hash_value.copy_advice(
                    || "hash_value",
                    &mut region,
                    self.config.hashes,
                    n_hashes,
                )?;

                // Assign hash accumulators
                // Note: we're not assigning from hash_accumulators[0], because
                //       assign_advice_from_constant() also constraints the cell to be 0
                region.assign_advice_from_constant(
                    || "hash accumulator 0",
                    self.config.hash_accumulator,
                    0,
                    F::ZERO,
                )?;
                // print_values("hash_accumulators", &hash_accumulators);
                for (i, hash_accumulator) in hash_accumulators.iter().enumerate() {
                    if i == 0 {
                        continue;
                    }

                    region.assign_advice(
                        || format!("hash accumulator{i}"),
                        self.config.hash_accumulator,
                        i,
                        || *hash_accumulator,
                    )?;
                }

                // Assign bloom index (same for all hashes)
                for i in 0..n_hashes {
                    region.assign_advice_from_constant(
                        || "bloom_index",
                        self.config.bloom_index,
                        i,
                        bloom_index,
                    )?;
                }

                // Assign bloom values
                // println!("bloom_index: {:?}", bloom_index);
                // print_values("bloom_values", &bloom_values);
                for (i, bloom_value) in bloom_values.iter().enumerate() {
                    region.assign_advice(
                        || format!("bloom_value_{i}"),
                        self.config.bloom_value,
                        i,
                        || *bloom_value,
                    )?;
                }

                // Assign bloom accumulators
                // Note: we're not assigning from bloom_accumulators[0], because
                //       assign_advice_from_constant() also constraints the cell to be 1
                region.assign_advice_from_constant(
                    || "bloom accumulator 0",
                    self.config.bloom_accumulator,
                    0,
                    F::ONE,
                )?;
                // print_values("bloom_accumulators", &bloom_accumulators);

                let mut bloom_response: Option<AssignedCell<F, F>> = None;
                for (i, bloom_accumulator) in bloom_accumulators.iter().enumerate() {
                    if i == 0 {
                        continue;
                    }

                    let cell = region.assign_advice(
                        || format!("bloom accumulator{i}"),
                        self.config.bloom_accumulator,
                        i,
                        || *bloom_accumulator,
                    )?;

                    // At the end of the loop, `bloom_response` will be equal to the response of the bloom filter
                    bloom_response = Some(cell);
                }

                // Set selectors
                for i in 0..n_hashes {
                    self.config
                        .validate_bloom_accumulators_selector
                        .enable(&mut region, i)?;
                    self.config
                        .bloom_filter_lookup_selector
                        .enable(&mut region, i)?;
                    self.config
                        .validate_hash_accumulators_selector
                        .enable(&mut region, i)?;
                }
                self.config
                    .hash_equality_selector
                    .enable(&mut region, n_hashes)?;

                Ok(bloom_response.unwrap())
            },
        )
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
    use ndarray::{array, Array2};

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
        advice_columns: [Column<Advice>; 5],
        instance: Column<Instance>,
    }

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;

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
            ];

            for advice in advice_columns {
                meta.enable_equality(advice);
            }
            meta.enable_equality(instance);

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let bloom_filter_config = BloomFilterConfig {
                n_hashes: 2,
                bits_per_hash: 2,
            };
            let bloom_filter_chip_config = BloomFilterChip::configure(
                meta,
                advice_columns[0],
                advice_columns[1],
                advice_columns[2],
                advice_columns[3],
                advice_columns[4],
                bloom_filter_config,
            );

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

            let mut bloom_filter_chip = BloomFilterChip::construct(config.bloom_filter_chip_config);
            bloom_filter_chip.load(&mut layouter, self.bloom_filter_arrays.clone())?;

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
    fn test_8_positive() {
        // -> Hashes to indices 0, and 2
        let k = 4;
        let circuit = MyCircuit::<Fp> {
            input: 8,
            bloom_index: 0,
            bloom_filter_arrays: array![[true, false, true, false]],
            _marker: PhantomData,
        };
        let output = Fp::from(1);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_8_negative() {
        // -> Hashes to indices 0, and 2
        let k = 4;
        let circuit = MyCircuit::<Fp> {
            input: 8,
            bloom_index: 0,
            bloom_filter_arrays: array![[true, true, false, true]],
            _marker: PhantomData,
        };
        let output = Fp::from(0);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_10_positive() {
        // -> Hashes to indices 2, and 2
        let k = 4;
        let circuit = MyCircuit::<Fp> {
            input: 10,
            bloom_index: 0,
            bloom_filter_arrays: array![[false, false, true, false]],
            _marker: PhantomData,
        };
        let output = Fp::from(1);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_3_negative() {
        // -> Hashes to indices 2, and 2
        let k = 4;
        let circuit = MyCircuit::<Fp> {
            input: 10,
            bloom_index: 0,
            bloom_filter_arrays: array![[true, true, false, true]],
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
        let root = root.titled("Hash Chip Layout", ("sans-serif", 60)).unwrap();

        let circuit = MyCircuit::<Fp> {
            input: 2,
            bloom_index: 0,
            bloom_filter_arrays: array![[true, false, false, true]],
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(4, &circuit, &root)
            .unwrap();
    }
}

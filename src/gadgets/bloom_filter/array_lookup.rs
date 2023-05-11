use std::marker::PhantomData;

use crate::utils::{decompose_word, enable_range, to_u32};
use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector, TableColumn,
    },
    poly::Rotation,
};
use ndarray::Array2;

pub struct LookupResult<F: PrimeField> {
    word: AssignedCell<F, F>,
    byte_index: AssignedCell<F, F>,
    bit_index: AssignedCell<F, F>,
}

pub(crate) trait ArrayLookupInstructions<F: PrimeField> {
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<Vec<LookupResult<F>>, Error>;
}

#[derive(Debug, Clone)]
pub struct ArrayLookupConfig {
    /// Number of hashes per bloom filter
    pub n_hashes: usize,

    pub bits_per_hash: usize,

    pub word_index_bits: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct ArrayLookupChipConfig {
    hash_decomposition: Column<Advice>,
    byte_index: Column<Advice>,
    bit_index: Column<Advice>,
    bloom_index: Column<Advice>,
    bloom_value: Column<Advice>,

    validate_hash_decomposition_selector: Selector,
    bloom_filter_lookup_selector: Selector,

    table_bloom_index: TableColumn,
    table_word_index: TableColumn,
    table_bloom_value: TableColumn,

    array_lookup_config: ArrayLookupConfig,
}

pub(crate) struct ArrayLookupChip<F: PrimeField> {
    config: ArrayLookupChipConfig,
    bloom_filter_arrays: Option<Array2<bool>>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> ArrayLookupChip<F> {
    pub(crate) fn construct(config: ArrayLookupChipConfig) -> Self {
        ArrayLookupChip {
            config,
            // Set to None initially, have to call load() before synthesis
            bloom_filter_arrays: None,
            _marker: PhantomData,
        }
    }

    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        hash_decomposition: Column<Advice>,
        byte_index: Column<Advice>,
        bit_index: Column<Advice>,
        bloom_index: Column<Advice>,
        bloom_value: Column<Advice>,
        bloom_filter_config: ArrayLookupConfig,
    ) -> ArrayLookupChipConfig {
        assert!(bloom_filter_config.bits_per_hash < 64);

        let validate_hash_decomposition_selector = meta.selector();
        meta.create_gate("validate_hash_decomposition", |meta| {
            let selector = meta.query_selector(validate_hash_decomposition_selector);

            let hash_decomposition_cur = meta.query_advice(hash_decomposition, Rotation::cur());
            let hash_decomposition_next = meta.query_advice(hash_decomposition, Rotation::next());
            let byte_index = meta.query_advice(byte_index, Rotation::cur());
            let bit_index = meta.query_advice(bit_index, Rotation::cur());

            let shift_multiplier = F::from(1 << bloom_filter_config.bits_per_hash);
            let two_pow_3 = F::from(1 << 3);
            Constraints::with_selector(
                selector,
                vec![
                    hash_decomposition_next * shift_multiplier + byte_index * two_pow_3 + bit_index
                        - hash_decomposition_cur,
                ],
            )
        });

        let table_bloom_index = meta.lookup_table_column();
        let table_word_index = meta.lookup_table_column();
        let table_bloom_value = meta.lookup_table_column();
        let bloom_filter_lookup_selector = meta.complex_selector();

        meta.lookup("bloom filter lookup", |meta| {
            let selector = meta.query_selector(bloom_filter_lookup_selector);

            let hash_decomposition_cur = meta.query_advice(hash_decomposition, Rotation::cur());
            let hash_decomposition_next = meta.query_advice(hash_decomposition, Rotation::next());
            let byte_index = meta.query_advice(byte_index, Rotation::cur());
            let bit_index = meta.query_advice(bit_index, Rotation::cur());

            let shift_multiplier = F::from(1 << bloom_filter_config.bits_per_hash);
            let two_pow_3 = F::from(1 << 3);
            let right_shift_multiplier = F::from(
                1 << (bloom_filter_config.bits_per_hash - bloom_filter_config.word_index_bits),
            )
            .invert()
            .unwrap();

            let current_hash = hash_decomposition_cur - hash_decomposition_next * shift_multiplier;

            let word_index =
                (current_hash - byte_index * two_pow_3 - bit_index) * right_shift_multiplier;

            let bloom_index = meta.query_advice(bloom_index, Rotation::cur());
            let bloom_value = meta.query_advice(bloom_value, Rotation::cur());

            let default_value = Expression::Constant(-F::ONE);
            let one = Expression::Constant(F::ONE);

            // Whenever the selector is inactive, we look up the tuple (-1, -1, -1), which is added to the table for this purpose
            let with_default = |x: Expression<F>| {
                selector.clone() * x + (one.clone() - selector.clone()) * default_value.clone()
            };

            vec![
                (with_default(bloom_index), table_bloom_index),
                (with_default(word_index), table_word_index),
                (with_default(bloom_value), table_bloom_value),
            ]
        });

        ArrayLookupChipConfig {
            // Advice Columns
            hash_decomposition,
            byte_index,
            bit_index,
            bloom_index,
            bloom_value,

            // Selectors
            validate_hash_decomposition_selector,
            bloom_filter_lookup_selector,

            // Table Columns
            table_bloom_index,
            table_word_index,
            table_bloom_value,

            array_lookup_config: bloom_filter_config,
        }
    }

    pub(crate) fn load(
        &mut self,
        layouter: &mut impl Layouter<F>,
        bloom_filter_arrays: Array2<bool>,
    ) -> Result<(), Error> {
        let bloom_filter_length = 1 << self.config.array_lookup_config.bits_per_hash;
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

impl<F: PrimeField> ArrayLookupInstructions<F> for ArrayLookupChip<F> {
    fn bloom_lookup(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_value: AssignedCell<F, F>,
        bloom_index: F,
    ) -> Result<Vec<LookupResult<F>>, Error> {
        layouter.assign_region(
            || "look up hash values",
            |mut region| {
                let n_hashes = self.config.array_lookup_config.n_hashes;
                let bits_per_hash = self.config.array_lookup_config.bits_per_hash;
                let word_index_bits = self.config.array_lookup_config.word_index_bits;

                let bloom_filter_arrays = self
                    .bloom_filter_arrays
                    .as_ref()
                    .expect("Should call load() before bloom_lookup()!");

                // Compute values to put in cells
                let hash_values = hash_value
                    .value()
                    .map(|hash_value| decompose_word(hash_value, n_hashes, bits_per_hash));

                let index_values: Value<Vec<(F, F, F)>> = hash_values.clone().map(|hash_values| {
                    hash_values
                        .iter()
                        .map(|hash_value| {
                            // Decompose hash into 3 index values
                            let hash_value = to_u32(hash_value);
                            let n_bits_byte_and_bit_indices = bits_per_hash - word_index_bits;
                            let byte_and_bit_index_mask = 1 << n_bits_byte_and_bit_indices - 1;

                            let word_index = hash_value >> n_bits_byte_and_bit_indices;
                            let byte_index = (hash_value & byte_and_bit_index_mask) >> 3;
                            let bit_index = hash_value & 0b111;
                            (
                                F::from(word_index as u64),
                                F::from(byte_index as u64),
                                F::from(bit_index as u64),
                            )
                        })
                        .collect()
                });

                let bloom_values = index_values
                    .clone()
                    .map(|index_values| {
                        let bloom_index = to_u32(&bloom_index) as usize;
                        let bloom_values: Vec<F> = index_values
                            .iter()
                            .map(|(word_index, _, _)| {
                                let word_index = to_u32(word_index) as usize;
                                let bloom_value = bloom_filter_arrays[(bloom_index, word_index)];
                                if bloom_value {
                                    F::ONE
                                } else {
                                    F::ZERO
                                }
                            })
                            .collect();
                        bloom_values
                    })
                    .transpose_vec(n_hashes);

                let hash_values = hash_values.transpose_vec(n_hashes);
                let index_values = index_values.transpose_vec(n_hashes);

                let mut hash_decomposition = vec![hash_value.value_field().evaluate()];
                let shift_factor = F::from(1 << bits_per_hash).invert().unwrap();
                for hash in hash_values {
                    let prev = hash_decomposition[hash_decomposition.len() - 1];
                    hash_decomposition.push(
                        hash.zip(prev)
                            .map(|(hash, prev)| (prev - hash) * shift_factor),
                    );
                }
                hash_decomposition[hash_decomposition.len() - 1]
                    .assert_if_known(|last_value| *last_value == F::ZERO);

                // Assign hash decomposition
                for (i, value) in hash_decomposition.iter().enumerate() {
                    let name = || format!("hash_decomposition_{i}");
                    let column = self.config.hash_decomposition;
                    if i == 0 {
                        // hash_decomposition[0] should be the same as hash_value,
                        // by using copy_advice() we also add an equality constraint
                        hash_value.copy_advice(name, &mut region, column, i)?;
                    } else if i < n_hashes {
                        region.assign_advice(name, column, i, || *value)?;
                    } else {
                        // hash_decomposition[n_hashes] should be zero,
                        // by using assign_advice_from_constant() we also add an equality constraint
                        region.assign_advice_from_constant(name, column, i, F::ZERO)?;
                    }
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
                let mut bloom_value_cells = vec![];
                for (i, bloom_value) in bloom_values.iter().enumerate() {
                    bloom_value_cells.push(region.assign_advice(
                        || format!("bloom_value_{i}"),
                        self.config.bloom_value,
                        i,
                        || *bloom_value,
                    )?);
                }

                // Assign byte and bit indices
                let mut byte_index_cells = vec![];
                let mut bit_index_cells = vec![];
                for (i, index_values_i) in index_values.iter().enumerate() {
                    byte_index_cells.push(region.assign_advice(
                        || format!("byte_index_{i}"),
                        self.config.byte_index,
                        i,
                        || index_values_i.map(|(_, byte_index, _)| byte_index),
                    )?);
                    bit_index_cells.push(region.assign_advice(
                        || format!("bit_index_{i}"),
                        self.config.bit_index,
                        i,
                        || index_values_i.map(|(_, _, bit_index)| bit_index),
                    )?);
                }

                enable_range(
                    &mut region,
                    self.config.validate_hash_decomposition_selector,
                    0..n_hashes,
                )?;
                enable_range(
                    &mut region,
                    self.config.bloom_filter_lookup_selector,
                    0..n_hashes,
                )?;

                Ok(byte_index_cells
                    .into_iter()
                    .zip(bit_index_cells)
                    .zip(bloom_value_cells)
                    .map(|((byte_index, bit_index), bloom_value)| LookupResult {
                        word: bloom_value,
                        byte_index,
                        bit_index,
                    })
                    .collect())
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
        ArrayLookupChip, ArrayLookupChipConfig, ArrayLookupConfig, ArrayLookupInstructions,
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
        bloom_filter_chip_config: ArrayLookupChipConfig,
        advice_columns: [Column<Advice>; 5],
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
            ];

            for advice in advice_columns {
                meta.enable_equality(advice);
            }
            meta.enable_equality(instance);

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let bloom_filter_config = ArrayLookupConfig {
                n_hashes: 2,
                bits_per_hash: 2,
            };
            let bloom_filter_chip_config = ArrayLookupChip::configure(
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

            let mut bloom_filter_chip = ArrayLookupChip::construct(config.bloom_filter_chip_config);
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
        let root = root
            .titled("Bloom filter Layout", ("sans-serif", 60))
            .unwrap();

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

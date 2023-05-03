use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, TableColumn},
};
use ndarray::{array, Array3};

use crate::gadgets::{
    bloom_filter::{
        BloomFilterChip, BloomFilterChipConfig, BloomFilterConfig, BloomFilterInstructions,
    },
    hash::{HashChip, HashConfig, HashInstructions},
    response_accumulator::ResponseAccumulatorInstructions,
};
use crate::gadgets::{
    hash::HashFunctionConfig,
    response_accumulator::{ResponseAccumulatorChip, ResponseAccumulatorChipConfig},
};

use super::range_check::load_range_check_lookup_table;

pub(crate) trait WnnInstructions<F: PrimeFieldBits> {
    fn predict(
        &self,
        layouter: impl Layouter<F>,
        bloom_filter_arrays: Array3<bool>,
        inputs: Vec<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error>;
}

#[derive(Debug, Clone)]
struct WnnConfig {
    hash_function_config: HashFunctionConfig,
    bloom_filter_config: BloomFilterConfig,
}

#[derive(Clone, Debug)]
pub struct WnnChipConfig<F: PrimeFieldBits> {
    hash_chip_config: HashConfig<F>,
    bloom_filter_chip_config: BloomFilterChipConfig,
    response_accumulator_chip_config: ResponseAccumulatorChipConfig,
}

struct WnnChip<F: PrimeFieldBits> {
    config: WnnChipConfig<F>,
}

impl<F: PrimeFieldBits> WnnChip<F> {
    fn construct(config: WnnChipConfig<F>) -> Self {
        WnnChip { config }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_columns: [Column<Advice>; 5],
        range_check_table: TableColumn,
        wnn_config: WnnConfig,
    ) -> WnnChipConfig<F> {
        let lookup_range_check_config =
            LookupRangeCheckConfig::configure(meta, advice_columns[0], range_check_table);

        let hash_chip_config = HashChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            advice_columns[4],
            lookup_range_check_config,
            wnn_config.hash_function_config.clone(),
        );
        let bloom_filter_chip_config = BloomFilterChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            advice_columns[4],
            wnn_config.bloom_filter_config.clone(),
        );
        let response_accumulator_chip_config =
            ResponseAccumulatorChip::configure(meta, advice_columns);
        WnnChipConfig {
            hash_chip_config,
            bloom_filter_chip_config,
            response_accumulator_chip_config,
        }
    }
}

impl<F: PrimeFieldBits> WnnInstructions<F> for WnnChip<F> {
    fn predict(
        &self,
        mut layouter: impl Layouter<F>,
        bloom_filter_arrays: Array3<bool>,
        inputs: Vec<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert_eq!(bloom_filter_arrays.shape()[1], inputs.len());

        let hash_chip = HashChip::construct(self.config.hash_chip_config.clone());
        let mut bloom_filter_chip =
            BloomFilterChip::<F>::construct(self.config.bloom_filter_chip_config.clone());
        let response_accumulator_chip = ResponseAccumulatorChip::<F>::construct(
            self.config.response_accumulator_chip_config.clone(),
        );

        let hashes = inputs
            .iter()
            .map(|input| hash_chip.hash(layouter.namespace(|| "hash"), *input))
            .collect::<Result<Vec<_>, _>>()?;

        let n_classes = bloom_filter_arrays.shape()[0];

        // Flatten array: from shape (N, C, B) to (N * C, B)
        let shape = bloom_filter_arrays.shape();
        let bloom_filter_arrays_flat = bloom_filter_arrays
            .clone()
            .into_shape((shape[0] * shape[1], shape[2]))
            .unwrap();
        bloom_filter_chip.load(&mut layouter, bloom_filter_arrays_flat)?;

        let mut responses = vec![];
        for c in 0..n_classes {
            responses.push(Vec::new());
            for (i, hash) in hashes.clone().iter().enumerate() {
                let array_index = c * hashes.len() + i;
                responses[c].push(bloom_filter_chip.bloom_lookup(
                    &mut layouter,
                    hash.clone(),
                    F::from(array_index as u64),
                )?);
            }
        }

        responses
            .iter()
            .map(|class_responses| {
                response_accumulator_chip.accumulate_responses(&mut layouter, class_responses)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

#[derive(Debug, Clone)]
pub struct WnnCircuitConfig<F: PrimeFieldBits> {
    wnn_chip_config: WnnChipConfig<F>,
    range_check_table: TableColumn,
    instance_column: Column<Instance>,
}

pub struct WnnCircuit<
    F: PrimeFieldBits,
    const P: u64,
    const L: usize,
    const N_HASHES: usize,
    const BITS_PER_HASH: usize,
    const BITS_PER_FILTER: usize,
> {
    inputs: Vec<u64>,
    bloom_filter_arrays: Array3<bool>,
    _marker: PhantomData<F>,
}

impl<
        F: PrimeFieldBits,
        const P: u64,
        const L: usize,
        const N_HASHES: usize,
        const BITS_PER_HASH: usize,
        const BITS_PER_FILTER: usize,
    > WnnCircuit<F, P, L, N_HASHES, BITS_PER_HASH, BITS_PER_FILTER>
{
    pub fn new(inputs: Vec<u64>, bloom_filter_arrays: Array3<bool>) -> Self {
        Self {
            inputs,
            bloom_filter_arrays,
            _marker: PhantomData,
        }
    }

    pub fn plot(&self, filename: &str, k: u32) {
        use plotters::prelude::*;

        let root = BitMapBackend::new(filename, (1024, 1 << (k + 4))).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Hash Chip Layout", ("sans-serif", 60)).unwrap();
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(k, self, &root)
            .unwrap();
    }
}

impl<
        F: PrimeFieldBits,
        const P: u64,
        const L: usize,
        const N_HASHES: usize,
        const BITS_PER_HASH: usize,
        const BITS_PER_FILTER: usize,
    > Circuit<F> for WnnCircuit<F, P, L, N_HASHES, BITS_PER_HASH, BITS_PER_FILTER>
{
    type Config = WnnCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: vec![],
            bloom_filter_arrays: array![[[]]],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let instance_column = meta.instance_column();

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
        meta.enable_equality(instance_column);

        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        let range_check_table = meta.lookup_table_column();

        let bloom_filter_config = BloomFilterConfig {
            n_hashes: N_HASHES,
            bits_per_hash: BITS_PER_FILTER,
        };
        let hash_function_config = HashFunctionConfig {
            p: P,
            l: L,
            n_bits: BITS_PER_HASH,
        };
        let wnn_config = WnnConfig {
            bloom_filter_config,
            hash_function_config,
        };
        WnnCircuitConfig {
            wnn_chip_config: WnnChip::configure(
                meta,
                advice_columns,
                range_check_table,
                wnn_config,
            ),
            range_check_table,
            instance_column,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        load_range_check_lookup_table(&mut layouter, config.range_check_table)?;
        let wnn_chip = WnnChip::construct(config.wnn_chip_config);

        let result = wnn_chip.predict(
            layouter.namespace(|| "predict_wnn"),
            self.bloom_filter_arrays.clone(),
            self.inputs.iter().map(|v| F::from(*v)).collect(),
        )?;

        for i in 0..result.len() {
            layouter.constrain_instance(result[i].cell(), config.instance_column, i)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::pasta::pallas::Base as Fp;
    use ndarray::array;

    use super::WnnCircuit;

    #[test]
    fn test() {
        let k = 9;
        let circuit = WnnCircuit::<Fp, 17, 4, 2, 3, 2> {
            inputs: vec![2, 7],
            bloom_filter_arrays: array![
                [[true, false, true, false], [true, true, false, false],],
                [[true, false, true, false], [true, true, false, true],],
            ],
            _marker: PhantomData,
        };

        // Expected result:
        // - ((2^3 % 17) % 16) = 8 -> Indices 2 & 0
        // - ((7^3 % 17) % 16) = 3 -> Indices 0 & 3
        // - Class 0: 1 + 0 = 1
        // - Class 1: 1 + 1 = 2
        let expected_result = vec![Fp::from(1), Fp::from(2)];

        let prover = MockProver::run(k, &circuit, vec![expected_result]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn plot() {
        WnnCircuit::<Fp, 17, 4, 2, 3, 2> {
            inputs: vec![2, 7],
            bloom_filter_arrays: array![
                [[true, false, true, false], [true, true, false, false],],
                [[true, false, true, false], [true, true, false, true],],
            ],
            _marker: PhantomData,
        }
        .plot("wnn-layout.png", 6);
    }
}

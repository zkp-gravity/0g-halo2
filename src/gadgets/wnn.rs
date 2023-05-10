use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
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

pub(crate) trait WnnInstructions<F: PrimeField> {
    fn predict(
        &self,
        layouter: &mut impl Layouter<F>,
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
pub struct WnnChipConfig {
    hash_chip_config: HashConfig,
    bloom_filter_chip_config: BloomFilterChipConfig,
    response_accumulator_chip_config: ResponseAccumulatorChipConfig,
}

struct WnnChip<F: PrimeField> {
    config: WnnChipConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> WnnChip<F> {
    fn construct(config: WnnChipConfig) -> Self {
        WnnChip {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_columns: [Column<Advice>; 5],
        wnn_config: WnnConfig,
    ) -> WnnChipConfig {
        let hash_chip_config = HashChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            advice_columns[4],
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

impl<F: PrimeField> WnnInstructions<F> for WnnChip<F> {
    fn predict(
        &self,
        layouter: &mut impl Layouter<F>,
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
            .map(|input| hash_chip.hash(layouter, *input))
            .collect::<Result<Vec<_>, _>>()?;

        let n_classes = bloom_filter_arrays.shape()[0];

        // Flatten array: from shape (N, C, B) to (N * C, B)
        let shape = bloom_filter_arrays.shape();
        let bloom_filter_arrays_flat = bloom_filter_arrays
            .clone()
            .into_shape((shape[0] * shape[1], shape[2]))
            .unwrap();
        bloom_filter_chip.load(layouter, bloom_filter_arrays_flat)?;

        let mut responses = vec![];
        for c in 0..n_classes {
            responses.push(Vec::new());
            for (i, hash) in hashes.clone().iter().enumerate() {
                let array_index = c * hashes.len() + i;
                responses[c].push(bloom_filter_chip.bloom_lookup(
                    layouter,
                    hash.clone(),
                    F::from(array_index as u64),
                )?);
            }
        }

        responses
            .iter()
            .map(|class_responses| {
                response_accumulator_chip.accumulate_responses(layouter, class_responses)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

#[derive(Debug, Clone)]
pub struct WnnCircuitConfig {
    wnn_chip_config: WnnChipConfig,
    instance_column: Column<Instance>,
}

pub struct WnnCircuit<
    F: PrimeField,
    const P: u64,
    const L: usize,
    const N_HASHES: usize,
    const BITS_PER_HASH: usize,
> {
    inputs: Vec<u64>,
    bloom_filter_arrays: Array3<bool>,
    _marker: PhantomData<F>,
}

impl<
        F: PrimeField,
        const P: u64,
        const L: usize,
        const N_HASHES: usize,
        const BITS_PER_HASH: usize,
    > WnnCircuit<F, P, L, N_HASHES, BITS_PER_HASH>
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

        let root = BitMapBackend::new(filename, (1024, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("WNN Layout", ("sans-serif", 60)).unwrap();
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(k, self, &root)
            .unwrap();
    }
}

pub struct CircuitParams {
    p: u64,
    l: usize,
    n_hashes: usize,
    bits_per_hash: usize,
}

impl Default for CircuitParams {
    fn default() -> Self {
        unimplemented!("Parameters have to be specified by hand!")
    }
}

impl<
        F: PrimeField,
        const P: u64,
        const L: usize,
        const N_HASHES: usize,
        const BITS_PER_HASH: usize,
    > Circuit<F> for WnnCircuit<F, P, L, N_HASHES, BITS_PER_HASH>
{
    type Config = WnnCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = CircuitParams;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: vec![],
            bloom_filter_arrays: array![[[]]],
            _marker: PhantomData,
        }
    }

    fn params(&self) -> Self::Params {
        CircuitParams {
            p: P,
            l: L,
            n_hashes: N_HASHES,
            bits_per_hash: BITS_PER_HASH,
        }
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
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

        let bloom_filter_config = BloomFilterConfig {
            n_hashes: params.n_hashes,
            bits_per_hash: params.bits_per_hash,
        };
        let hash_function_config = HashFunctionConfig {
            p: params.p,
            l: params.l,
        };
        let wnn_config = WnnConfig {
            bloom_filter_config,
            hash_function_config,
        };
        WnnCircuitConfig {
            wnn_chip_config: WnnChip::configure(meta, advice_columns, wnn_config),
            instance_column,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let wnn_chip = WnnChip::construct(config.wnn_chip_config);

        let result = wnn_chip.predict(
            &mut layouter,
            self.bloom_filter_arrays.clone(),
            self.inputs.iter().map(|v| F::from(*v)).collect(),
        )?;

        for i in 0..result.len() {
            layouter.constrain_instance(result[i].cell(), config.instance_column, i)?;
        }

        Ok(())
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        unimplemented!("configure_with_params should be used!")
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use ndarray::array;

    use super::WnnCircuit;

    #[test]
    fn test() {
        let k = 6;
        let circuit = WnnCircuit::<Fp, 17, 4, 2, 2> {
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
        WnnCircuit::<Fp, 17, 4, 2, 2> {
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

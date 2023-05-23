use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use ndarray::{array, Array3};

use crate::gadgets::{
    bloom_filter::{BloomFilterChip, BloomFilterChipConfig},
    bloom_filter::{BloomFilterConfig, BloomFilterInstructions},
    hash::{HashChip, HashConfig, HashInstructions},
    range_check::RangeCheckConfig,
    response_accumulator::ResponseAccumulatorInstructions,
};
use crate::gadgets::{
    hash::HashFunctionConfig,
    response_accumulator::{ResponseAccumulatorChip, ResponseAccumulatorChipConfig},
};

pub trait WnnInstructions<F: PrimeFieldBits> {
    /// Given an input vector, predicts the score for each class.
    fn predict(
        &self,
        layouter: impl Layouter<F>,
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

/// Implements a BTHOWeN- style weightless neural network.
///
/// This happens in three steps:
/// 1. The [`HashChip`] is used to range-check and hash the inputs.
/// 2. The [`BloomFilterChip`] is used to look up the bloom filter responses
///    (for each input and each class).
/// 3. The [`ResponseAccumulatorChip`] is used to accumulate the responses.
struct WnnChip<F: PrimeFieldBits> {
    hash_chip: HashChip<F>,
    bloom_filter_chip: BloomFilterChip<F>,
    response_accumulator_chip: ResponseAccumulatorChip<F>,

    n_classes: usize,
    n_inputs: usize,
}

impl<F: PrimeFieldBits> WnnChip<F> {
    fn construct(config: WnnChipConfig<F>, bloom_filter_arrays: Array3<bool>) -> Self {
        let n_classes = bloom_filter_arrays.shape()[0];
        let n_inputs = bloom_filter_arrays.shape()[1];

        let hash_chip = HashChip::construct(config.hash_chip_config.clone());
        let bloom_filter_chip = BloomFilterChip::construct(
            config.bloom_filter_chip_config.clone(),
            bloom_filter_arrays,
        );
        let response_accumulator_chip =
            ResponseAccumulatorChip::construct(config.response_accumulator_chip_config.clone());

        WnnChip {
            hash_chip,
            bloom_filter_chip,
            response_accumulator_chip,
            n_classes,
            n_inputs,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_columns: [Column<Advice>; 6],
        wnn_config: WnnConfig,
    ) -> WnnChipConfig<F> {
        let bloom_filter_chip_config = BloomFilterChip::configure(
            meta,
            advice_columns,
            wnn_config.bloom_filter_config.clone(),
        );
        let lookup_range_check_config = RangeCheckConfig::configure(
            meta,
            advice_columns[0],
            // Re-use byte column of the bloom filter
            bloom_filter_chip_config.byte_column,
        );
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
        let response_accumulator_chip_config =
            ResponseAccumulatorChip::configure(meta, advice_columns[0..5].try_into().unwrap());
        WnnChipConfig {
            hash_chip_config,
            bloom_filter_chip_config,
            response_accumulator_chip_config,
        }
    }

    pub fn load(&mut self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.bloom_filter_chip.load(layouter)
    }
}

impl<F: PrimeFieldBits> WnnInstructions<F> for WnnChip<F> {
    fn predict(
        &self,
        mut layouter: impl Layouter<F>,
        inputs: Vec<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert_eq!(self.n_inputs, inputs.len());

        let hashes = inputs
            .iter()
            .map(|input| self.hash_chip.hash(layouter.namespace(|| "hash"), *input))
            .collect::<Result<Vec<_>, _>>()?;

        let mut responses = vec![];
        for c in 0..self.n_classes {
            responses.push(Vec::new());
            for (i, hash) in hashes.clone().into_iter().enumerate() {
                let array_index = c * hashes.len() + i;
                responses[c].push(self.bloom_filter_chip.bloom_lookup(
                    &mut layouter,
                    hash,
                    F::from(array_index as u64),
                )?);
            }
        }

        responses
            .iter()
            .map(|class_responses| {
                self.response_accumulator_chip
                    .accumulate_responses(&mut layouter, class_responses)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

#[derive(Debug, Clone)]
pub struct WnnCircuitConfig<F: PrimeFieldBits> {
    wnn_chip_config: WnnChipConfig<F>,
    instance_column: Column<Instance>,
}

#[derive(Clone)]
pub struct WnnCircuitParams {
    pub p: u64,
    pub l: usize,
    pub n_hashes: usize,
    pub bits_per_hash: usize,
    pub bits_per_filter: usize,
}

pub struct WnnCircuit<F: PrimeFieldBits> {
    inputs: Vec<u64>,
    bloom_filter_arrays: Array3<bool>,
    params: WnnCircuitParams,
    _marker: PhantomData<F>,
}

impl<F: PrimeFieldBits> WnnCircuit<F> {
    pub fn new(
        inputs: Vec<u64>,
        bloom_filter_arrays: Array3<bool>,
        params: WnnCircuitParams,
    ) -> Self {
        Self {
            inputs,
            bloom_filter_arrays,
            params,
            _marker: PhantomData,
        }
    }

    pub fn plot(&self, filename: &str, k: u32) {
        use plotters::prelude::*;

        let root = BitMapBackend::new(filename, (1024, 1 << (k + 3))).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("WNN Layout", ("sans-serif", 60)).unwrap();
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(k, self, &root)
            .unwrap();
    }
}

impl Default for WnnCircuitParams {
    fn default() -> Self {
        unimplemented!("Parameters have to be specified manually!")
    }
}

impl<F: PrimeFieldBits> Circuit<F> for WnnCircuit<F> {
    type Config = WnnCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = WnnCircuitParams;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: vec![],
            bloom_filter_arrays: array![[[]]],
            params: self.params.clone(),
            _marker: PhantomData,
        }
    }

    fn params(&self) -> Self::Params {
        self.params.clone()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let instance_column = meta.instance_column();

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
            n_bits: params.bits_per_filter,
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
        let mut wnn_chip =
            WnnChip::construct(config.wnn_chip_config, self.bloom_filter_arrays.clone());
        wnn_chip.load(&mut layouter)?;

        let result = wnn_chip.predict(
            layouter.namespace(|| "wnn"),
            self.inputs.iter().map(|v| F::from(*v)).collect(),
        )?;

        for i in 0..result.len() {
            layouter.constrain_instance(result[i].cell(), config.instance_column, i)?;
        }

        Ok(())
    }

    fn configure(_meta: &mut ConstraintSystem<F>) -> Self::Config {
        unimplemented!("configure_with_params should be used!")
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use ndarray::Array3;

    use super::{WnnCircuit, WnnCircuitParams};

    const PARAMS: WnnCircuitParams = WnnCircuitParams {
        p: (1 << 21) - 9,
        l: 20,
        n_hashes: 2,
        bits_per_hash: 10,
        bits_per_filter: 15,
    };

    #[test]
    fn test() {
        let k = 13;
        let input = vec![2117, 30177];
        // The input numbers hash to the following indices:
        // - 2117 -> (2117^3) % (2^21 - 9) % (1024^2) = 260681
        //   - 260681 % 1024 = 585
        //   - 260681 // 1024 = 254
        // - 30177 -> (30177^3) % (2^21 - 9) % (1024^2) = 260392
        //   - 260392 % 1024 = 296
        //   - 260392 // 1024 = 254
        // We'll set the bloom filter such that we get one positive response for he first
        // class and two positive responses for the second class.
        let mut bloom_filter_arrays = Array3::<u8>::ones((3, 2, 1024)).mapv(|_| false);
        // First class
        bloom_filter_arrays[[0, 0, 585]] = true;
        bloom_filter_arrays[[0, 0, 254]] = true;
        bloom_filter_arrays[[0, 1, 296]] = true;
        // Second class
        bloom_filter_arrays[[1, 0, 585]] = true;
        bloom_filter_arrays[[1, 0, 254]] = true;
        bloom_filter_arrays[[1, 1, 296]] = true;
        bloom_filter_arrays[[1, 1, 254]] = true;

        let circuit = WnnCircuit::<Fp>::new(input, bloom_filter_arrays, PARAMS);

        let expected_result = vec![Fp::from(1), Fp::from(2)];

        let prover = MockProver::run(k, &circuit, vec![expected_result]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn plot() {
        let bloom_filter_arrays = Array3::<u8>::ones((2, 2, 1024)).mapv(|_| true);
        WnnCircuit::<Fp>::new(vec![2, 7], bloom_filter_arrays, PARAMS).plot("wnn-layout.png", 8);
    }
}

use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2_proofs::circuit::Value;
use ndarray::{array, Array3};

use crate::gadgets::{
    bloom_filter::{BloomFilterChip, BloomFilterChipConfig},
    bloom_filter::{BloomFilterConfig, BloomFilterInstructions},
    hash::{HashChip, HashConfig, HashInstructions},
    range_check::RangeCheckConfig,
    response_accumulator::ResponseAccumulatorInstructions,
    bits2num::{Bits2NumChip, Bits2NumChipConfig, Bits2NumConfig, Bits2NumInstruction},
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
        bloom_filter_arrays: Array3<bool>,
        inputs: Vec<bool>,
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
    bit2num_chip_config: Bits2NumChipConfig,
}

/// Implements a BTHOWeN- style weightless neural network.
/// 
/// This happens in three steps:
/// 1. The [`HashChip`] is used to range-check and hash the inputs.
/// 2. The [`BloomFilterChip`] is used to look up the bloom filter responses
///    (for each input and each class).
/// 3. The [`ResponseAccumulatorChip`] is used to accumulate the responses.
struct WnnChip<F: PrimeFieldBits> {
    config: WnnChipConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: PrimeFieldBits> WnnChip<F> {
    fn construct(config: WnnChipConfig<F>) -> Self {
        WnnChip {
            config,
            _marker: PhantomData,
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

        let bit2num_chip_config = Bits2NumChip::configure(
            meta,
            advice_columns[1], // TODO - how do we select the correct column? I just picked the second one
            advice_columns[5], // TODO - how do we select the correct column? I just picked the last one
            Bits2NumConfig {
                num_bit_size: wnn_config.hash_function_config.n_bits
            },
        );

        WnnChipConfig {
            hash_chip_config,
            bloom_filter_chip_config,
            response_accumulator_chip_config,
            bit2num_chip_config,
        }
    }
}

impl<F: PrimeFieldBits> WnnInstructions<F> for WnnChip<F> {
    fn predict(
        &self,
        mut layouter: impl Layouter<F>,
        bloom_filter_arrays: Array3<bool>,
        inputs: Vec<bool>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert_eq!(self.config.hash_chip_config.hash_function_config.n_bits * bloom_filter_arrays.shape()[1], inputs.len());

        // Flatten array: from shape (C, N, B) to (C * N, B)
        let shape = bloom_filter_arrays.shape();
        let bloom_filter_arrays_flat = bloom_filter_arrays
            .clone()
            .into_shape((shape[0] * shape[1], shape[2]))
            .unwrap();


        let bit2num_chip = Bits2NumChip::<F>::construct(self.config.bit2num_chip_config.clone());

        let hash_chip = HashChip::construct(self.config.hash_chip_config.clone());
        let mut bloom_filter_chip = BloomFilterChip::<F>::construct(
            self.config.bloom_filter_chip_config.clone(),
            bloom_filter_arrays_flat,
        );
        let response_accumulator_chip = ResponseAccumulatorChip::<F>::construct(
            self.config.response_accumulator_chip_config.clone(),
        );

        // Assign the inputs to the first column of the hash chip
        let mut permuted_inputs = vec![];
        layouter.assign_region(|| "permuted inputs", |mut region| {
            for (i, input) in inputs.iter().enumerate() {
                let input_cell = region.assign_advice(
                    || format!("input {}", i),
                    self.config.bit2num_chip_config.input,
                    i,
                    || Value::known(F::from(*input as u64)),
                )?;

                permuted_inputs.push(input_cell);
            }
            Ok(())
        })?;

        // Convert the input bits to a group of field element that can be hashed
        let joint_inputs : Vec<AssignedCell<F, F>> = permuted_inputs
            .chunks_exact(self.config.bit2num_chip_config.bit2num_config.num_bit_size)
            .map(|chunk| {
                bit2num_chip
                    .convert_le(
                        &mut layouter,
                        Vec::from(chunk),
                    )
                    .unwrap()
            })
            .collect();

        let hashes = joint_inputs
            .iter()
            .map(|hash_input| hash_chip.hash(layouter.namespace(|| "hash"), hash_input.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        let n_classes = bloom_filter_arrays.shape()[0];
        bloom_filter_chip.load(&mut layouter)?;

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
    inputs: Vec<bool>,
    bloom_filter_arrays: Array3<bool>,
    params: WnnCircuitParams,
    _marker: PhantomData<F>,
}

impl<F: PrimeFieldBits> WnnCircuit<F> {
    pub fn new(
        inputs: Vec<bool>,
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
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let wnn_chip = WnnChip::construct(config.wnn_chip_config);

        let result = wnn_chip.predict(
            layouter.namespace(|| "wnn"),
            self.bloom_filter_arrays.clone(),
            self.inputs.clone()
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
        let input = vec![true, false, true, false, false, false, true, false, false, false, false, true, false, false, false, true, false, false, false, false, true, true, true, true, false, true, false, true, true, true];
        // First, we join the bits into two 15 bit numbers 2117 and 30177
        // Then joint input numbers hash to the following indices:
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
        // This is the input that will be joint into [2, 7]
        let inputs = vec![false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, true, false, false, false, false, false, false, false, false, false, false, false, false];
        WnnCircuit::<Fp>::new(inputs, bloom_filter_arrays, PARAMS).plot("wnn-layout.png", 8);
    }
}

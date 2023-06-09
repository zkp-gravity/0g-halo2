//! Implementation of a gadget & circuit implementing a [BTHOWeN](https://arxiv.org/abs/2203.01479)-style weightless neural network (WNN).

use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use ndarray::{Array1, Array2, Array3};
use serde::{Deserialize, Serialize};

use crate::gadgets::{
    bits2num::{Bits2NumChip, Bits2NumChipConfig, Bits2NumInstruction},
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

use super::encode_image::{EncodeImageChip, EncodeImageChipConfig, EncodeImageInstructions};

/// Instructions for the [`WnnChip`].
pub trait WnnInstructions<F: PrimeFieldBits> {
    /// Given an input vector, predicts the score for each class.
    fn predict(
        &self,
        layouter: impl Layouter<F>,
        image: Value<Array2<u8>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error>;
}

/// Configuration of the WNN.
#[derive(Debug, Clone)]
pub struct WnnConfig {
    pub hash_function_config: HashFunctionConfig,
    pub bloom_filter_config: BloomFilterConfig,
}

#[derive(Clone, Debug)]
pub struct WnnChipConfig<F: PrimeFieldBits> {
    encode_image_chip_config: EncodeImageChipConfig<F>,
    bits2num_chip_config: Bits2NumChipConfig,
    hash_chip_config: HashConfig<F>,
    bloom_filter_chip_config: BloomFilterChipConfig,
    response_accumulator_chip_config: ResponseAccumulatorChipConfig,
}

/// Implements a BTHOWeN- style weightless neural network.
///
/// This happens in the following steps:
/// 1. The [`EncodeImageChip`] is used to binarize the input image.
/// 2. The input bits are permuted.
/// 3. The [`Bits2NumChip`] is used to convert the bits to numbers.
/// 4. The [`HashChip`] hash the wach number.
/// 5. The [`BloomFilterChip`] is used to look up the bloom filter responses
///    (for each input and each class).
/// 6. The [`ResponseAccumulatorChip`] is used to accumulate the responses.
pub struct WnnChip<F: PrimeFieldBits> {
    encode_image_chip: EncodeImageChip<F>,
    bits2num_chip: Bits2NumChip<F>,
    hash_chip: HashChip<F>,
    bloom_filter_chip: BloomFilterChip<F>,
    response_accumulator_chip: ResponseAccumulatorChip<F>,

    input_permutation: Array1<u64>,

    config: WnnChipConfig<F>,

    n_classes: usize,
    n_inputs: usize,
}

impl<F: PrimeFieldBits> WnnChip<F> {
    pub fn construct(
        config: WnnChipConfig<F>,
        bloom_filter_arrays: Array3<bool>,
        binarization_thresholds: Array3<u16>,
        input_permutation: Array1<u64>,
    ) -> Self {
        let shape = bloom_filter_arrays.shape();
        let n_classes = shape[0];
        let n_inputs = shape[1];
        let n_filters = shape[2];

        // Flatten array: from shape (C, N, B) to (C * N, B)
        let bloom_filter_arrays_flat = bloom_filter_arrays
            .into_shape((n_classes * n_inputs, n_filters))
            .unwrap();

        let encode_image_chip = EncodeImageChip::construct(
            config.encode_image_chip_config.clone(),
            binarization_thresholds,
        );
        let bits2num_chip = Bits2NumChip::construct(config.bits2num_chip_config.clone());
        let hash_chip = HashChip::construct(config.hash_chip_config.clone());
        let bloom_filter_chip = BloomFilterChip::construct(
            config.bloom_filter_chip_config.clone(),
            &bloom_filter_arrays_flat,
        );
        let response_accumulator_chip =
            ResponseAccumulatorChip::construct(config.response_accumulator_chip_config.clone());

        WnnChip {
            encode_image_chip,
            bits2num_chip,
            hash_chip,
            bloom_filter_chip,
            response_accumulator_chip,

            input_permutation,

            config,

            n_classes,
            n_inputs,
        }
    }

    pub fn configure(
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
            advice_columns[5],
            // Re-use byte column of the bloom filter
            bloom_filter_chip_config.byte_column,
        );
        let encode_image_chip_config = EncodeImageChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            lookup_range_check_config.clone(),
        );
        let hash_chip_config = HashChip::configure(
            meta,
            advice_columns[0],
            advice_columns[1],
            advice_columns[2],
            advice_columns[3],
            advice_columns[4],
            lookup_range_check_config,
            wnn_config.hash_function_config,
        );
        let response_accumulator_chip_config =
            ResponseAccumulatorChip::configure(meta, advice_columns[0..5].try_into().unwrap());

        let bits2num_chip_config =
            Bits2NumChip::configure(meta, advice_columns[3], advice_columns[4]);

        WnnChipConfig {
            encode_image_chip_config,
            hash_chip_config,
            bloom_filter_chip_config,
            response_accumulator_chip_config,
            bits2num_chip_config,
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
        image: Value<Array2<u8>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let bit_cells = self
            .encode_image_chip
            .encode_image(layouter.namespace(|| "encode image"), image)?;

        // Permute input bits
        let permuted_inputs = self
            .input_permutation
            .iter()
            .map(|i| bit_cells[*i as usize].clone())
            .collect::<Vec<_>>();

        let num_bit_size = self.config.hash_chip_config.hash_function_config.n_bits;

        // Convert the input bits to a group of field element that can be hashed
        let joint_inputs = permuted_inputs
            .chunks_exact(num_bit_size)
            .map(|chunk| {
                self.bits2num_chip
                    .convert_le(&mut layouter, Vec::from(chunk))
            })
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(self.n_inputs, joint_inputs.len());

        let hashes = joint_inputs
            .into_iter()
            .map(|hash_input| {
                self.hash_chip
                    .hash(layouter.namespace(|| "hash"), hash_input)
            })
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

#[derive(Clone, Serialize, Deserialize)]
pub struct WnnCircuitParams {
    pub p: u64,
    pub l: usize,
    pub n_hashes: usize,
    pub bits_per_hash: usize,
    pub bits_per_filter: usize,
    pub n_classes: usize,
}

/// A circuit using [`WnnChip`] to predict the class of an (secret) image.
#[derive(Clone)]
pub struct WnnCircuit<F: PrimeFieldBits> {
    image: Value<Array2<u8>>,
    bloom_filter_arrays: Array3<bool>,
    binarization_thresholds: Array3<u16>,
    input_permutation: Array1<u64>,
    params: WnnCircuitParams,
    _marker: PhantomData<F>,
}

impl<F: PrimeFieldBits> WnnCircuit<F> {
    pub fn new(
        image: Array2<u8>,
        bloom_filter_arrays: Array3<bool>,
        binarization_thresholds: Array3<u16>,
        input_permutation: Array1<u64>,
        params: WnnCircuitParams,
    ) -> Self {
        assert_eq!(bloom_filter_arrays.shape()[0], params.n_classes);
        Self {
            image: Value::known(image),
            bloom_filter_arrays,
            binarization_thresholds,
            input_permutation,
            params,
            _marker: PhantomData,
        }
    }

    /// Plot the circuit circuit layout, outputting to a particular file.
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

    // The V1 floor planner could be used for fewer number of rows,
    // but unfortunately, it has aproving time overhead of ~30%.
    // Also, it rarely leads to smaller values of `k` in practice,
    // so we stick with SimpleFloorPlanner for now.
    // In principle, there is no good reason for a proving time overhead
    // of floor planning, and there are plans to get rid of it:
    // https://github.com/zcash/halo2/issues/547
    type FloorPlanner = SimpleFloorPlanner;
    type Params = WnnCircuitParams;

    fn without_witnesses(&self) -> Self {
        Self {
            image: Value::unknown(),
            bloom_filter_arrays: self.bloom_filter_arrays.clone(),
            binarization_thresholds: self.binarization_thresholds.clone(),
            input_permutation: self.input_permutation.clone(),
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
        let mut wnn_chip = WnnChip::construct(
            config.wnn_chip_config,
            self.bloom_filter_arrays.clone(),
            self.binarization_thresholds.clone(),
            self.input_permutation.clone(),
        );
        wnn_chip.load(&mut layouter)?;

        let result = wnn_chip.predict(layouter.namespace(|| "wnn"), self.image.clone())?;

        for (i, score) in result.iter().enumerate() {
            layouter.constrain_instance(score.cell(), config.instance_column, i)?;
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
    use ndarray::{array, Array3};

    use super::{WnnCircuit, WnnCircuitParams};

    const PARAMS: WnnCircuitParams = WnnCircuitParams {
        p: 2097143, // (1 << 21) - 9
        l: 20,
        n_hashes: 2,
        bits_per_hash: 10,
        bits_per_filter: 12,
        n_classes: 2,
    };

    fn make_test_circuit() -> WnnCircuit<Fp> {
        // A 4x3 image
        let image = array![[70, 100, 150], [20, 110, 200], [27, 50, 211], [200, 100, 3]];
        // Two thresholds for each pixel
        let binarization_thresholds = array![
            [[50, 150], [0, 50], [200, 256]],
            [[10, 80], [100, 200], [50, 150]],
            [[0, 100], [100, 200], [0, 100]],
            [[0, 100], [100, 200], [0, 100]]
        ];
        // -> This leads to the bit vector [
        //     // First threshold
        //     1, 1, 0,
        //     1, 1, 1,
        //     1, 0, 1,
        //     1, 1, 1,
        //     // Second threshold
        //     0, 1, 0,
        //     0, 0, 1,
        //     0, 0, 1,
        //     1, 0, 0
        // ]
        let input_permutation = array![
            6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 0, 1, 2, 3, 4, 5
        ];
        // --> This leads to the bit vector:[
        //     1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1,
        //     0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1
        // ]
        // --> By interpreting it as 2 little endian number representations, we get indices:
        //     2237, 3788
        // --> The corresponding MishMash hashes are and indices:
        //     - 2237 -> (2237^3) % 2097143 % (2^20) = 825286
        //       - 825286 % 1024 = 966
        //       - 825286 // 1024 = 805
        //     - 3788 -> (3788^3) % 2097143 % (2^20) = 47598
        //       - 47598 % 1024 = 494
        //       - 47598 // 1024 = 46
        // --> We'll set the bloom filter such that we get one positive response for he first
        //     class and two positive responses for the second class.
        let mut bloom_filter_arrays = Array3::<u8>::ones((2, 2, 1024)).mapv(|_| false);
        // First class
        bloom_filter_arrays[[0, 0, 966]] = true;
        bloom_filter_arrays[[0, 0, 805]] = true;
        bloom_filter_arrays[[0, 1, 494]] = true;
        // Second class
        bloom_filter_arrays[[1, 0, 966]] = true;
        bloom_filter_arrays[[1, 0, 805]] = true;
        bloom_filter_arrays[[1, 1, 494]] = true;
        bloom_filter_arrays[[1, 1, 46]] = true;

        WnnCircuit::new(
            image,
            bloom_filter_arrays,
            binarization_thresholds,
            input_permutation,
            PARAMS,
        )
    }

    #[test]
    fn test() {
        let k = 13;

        let circuit = make_test_circuit();

        let expected_result = vec![Fp::from(1), Fp::from(2)];

        let prover = MockProver::run(k, &circuit, vec![expected_result]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn plot() {
        make_test_circuit().plot("wnn-layout.png", 9);
    }
}

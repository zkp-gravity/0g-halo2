use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    pasta::group::ff::{PrimeField, PrimeFieldBits},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
};

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
        bloom_filter_arrays: Vec<Vec<Vec<bool>>>,
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

impl<F: PrimeField + PrimeFieldBits> WnnInstructions<F> for WnnChip<F> {
    fn predict(
        &self,
        layouter: &mut impl Layouter<F>,
        bloom_filter_arrays: Vec<Vec<Vec<bool>>>,
        inputs: Vec<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert_eq!(bloom_filter_arrays.len(), inputs.len());

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

        let n_classes = bloom_filter_arrays[0].len();
        for bloom_filter_array in &bloom_filter_arrays {
            assert_eq!(bloom_filter_array.len(), n_classes);
        }

        // Flatten array: from shape (N, C, B) to (N * C, B)
        let bloom_filter_arrays_flat = bloom_filter_arrays
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        bloom_filter_chip.load(layouter, bloom_filter_arrays_flat)?;

        let mut responses = vec![];
        for c in 0..n_classes {
            responses.push(Vec::new());
            for (i, hash) in hashes.clone().iter().enumerate() {
                let array_index = i * n_classes + c;
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

pub struct WnnCircuit<
    F: PrimeField,
    const P: u64,
    const L: usize,
    const N_HASHES: usize,
    const BITS_PER_HASH: usize,
> {
    inputs: Vec<u64>,
    bloom_filter_arrays: Vec<Vec<Vec<bool>>>,
    _marker: PhantomData<F>,
}

impl<
        F: PrimeFieldBits,
        const P: u64,
        const L: usize,
        const N_HASHES: usize,
        const BITS_PER_HASH: usize,
    > Circuit<F> for WnnCircuit<F, P, L, N_HASHES, BITS_PER_HASH>
{
    type Config = WnnChipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: vec![],
            bloom_filter_arrays: vec![vec![]],
            _marker: PhantomData,
        }
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
            n_hashes: N_HASHES,
            bits_per_hash: BITS_PER_HASH,
        };
        let hash_function_config = HashFunctionConfig { p: P, l: L };
        let wnn_config = WnnConfig {
            bloom_filter_config,
            hash_function_config,
        };
        WnnChip::configure(meta, advice_columns, wnn_config)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let wnn_chip = WnnChip::construct(config);

        wnn_chip.predict(
            &mut layouter,
            self.bloom_filter_arrays.clone(),
            self.inputs.iter().map(|v| F::from(*v)).collect(),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use halo2_proofs::{dev::MockProver, pasta::Fp};

    use super::WnnCircuit;

    #[test]
    fn test() {
        let k = 6;
        let circuit = WnnCircuit::<Fp, 17, 4, 2, 2> {
            inputs: vec![2, 7],
            bloom_filter_arrays: vec![
                vec![
                    vec![true, false, true, false],
                    vec![true, true, false, false],
                ],
                vec![
                    vec![true, false, true, false],
                    vec![true, true, false, false],
                ],
            ],
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("wnn-layout.png", (1024, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Hash Chip Layout", ("sans-serif", 60)).unwrap();

        let circuit = WnnCircuit::<Fp, 17, 4, 2, 2> {
            inputs: vec![2, 7],
            bloom_filter_arrays: vec![
                vec![
                    vec![true, false, true, false],
                    vec![true, true, false, false],
                ],
                vec![
                    vec![true, false, true, false],
                    vec![true, true, false, false],
                ],
            ],
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(6, &circuit, &root)
            .unwrap();
    }
}

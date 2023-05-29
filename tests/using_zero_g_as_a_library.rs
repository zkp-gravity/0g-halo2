//! A simulation of someone using zero_g as a library.
//! This basically reimplements [`zero_g::wnn::WnnCircuit`].
//! No code is run, it just has to compile, which ensures that all necessary data structures are public.

use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use ndarray::{Array1, Array2, Array3};
use zero_g::gadgets::{
    bloom_filter::BloomFilterConfig,
    hash::HashFunctionConfig,
    wnn::{WnnChipConfig, WnnConfig, WnnInstructions},
    WnnChip,
};

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
    image: Array2<u8>,
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
        Self {
            image,
            bloom_filter_arrays,
            binarization_thresholds,
            input_permutation,
            params,
            _marker: PhantomData,
        }
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
        unimplemented!()
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

        let result = wnn_chip.predict(layouter.namespace(|| "wnn"), &self.image)?;

        for (i, score) in result.iter().enumerate() {
            layouter.constrain_instance(score.cell(), config.instance_column, i)?;
        }

        Ok(())
    }

    fn configure(_meta: &mut ConstraintSystem<F>) -> Self::Config {
        unimplemented!("configure_with_params should be used!")
    }
}

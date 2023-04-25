use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    pasta::group::ff::PrimeField,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use num_bigint::BigUint;

use crate::utils::integer_division;

pub(crate) trait HashInstructions<F: PrimeField> {
    fn hash(&self, layouter: &mut impl Layouter<F>, input: F) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub(crate) struct HashFunctionConfig {
    /// Prime to use in the hash function
    pub(crate) p: u64,
    /// number of bits for the hash function output
    pub(crate) l: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct HashConfig {
    selector: Selector,
    input: Column<Advice>,
    quotient: Column<Advice>,
    remainder: Column<Advice>,
    msb: Column<Advice>,
    hash: Column<Advice>,
    pub(crate) hash_function_config: HashFunctionConfig,
}

#[derive(Debug, Clone)]
pub(crate) struct HashChip<F: PrimeField> {
    config: HashConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> HashChip<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        input: Column<Advice>,
        quotient: Column<Advice>,
        remainder: Column<Advice>,
        msb: Column<Advice>,
        hash: Column<Advice>,
        hash_function_config: HashFunctionConfig,
    ) -> HashConfig {
        let selector = meta.selector();

        meta.create_gate("hash", |meta| {
            let selector = meta.query_selector(selector);

            let input = meta.query_advice(input, Rotation::cur());
            let quotient = meta.query_advice(quotient, Rotation::cur());
            let remainder = meta.query_advice(remainder, Rotation::cur());
            let msb = meta.query_advice(msb, Rotation::cur());
            let hash = meta.query_advice(hash, Rotation::cur());

            // TODO: Handle possible overflows
            let input_cubed = input.clone() * input.clone() * input;
            let mod_p_decomposition = quotient
                * Expression::Constant(F::from(hash_function_config.p))
                + remainder.clone();
            let mod_2l_decomposition =
                msb * Expression::Constant(F::from(1 << hash_function_config.l)) + hash;

            Constraints::with_selector(
                selector,
                vec![
                    input_cubed - mod_p_decomposition,
                    remainder - mod_2l_decomposition,
                ],
            )
        });

        HashConfig {
            selector,
            input,
            quotient,
            remainder,
            msb,
            hash,
            hash_function_config,
        }
    }

    pub(crate) fn construct(config: HashConfig) -> Self {
        HashChip {
            config,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> HashInstructions<F> for HashChip<F> {
    fn hash(&self, layouter: &mut impl Layouter<F>, input: F) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "hash",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let HashFunctionConfig { p, l } = self.config.hash_function_config;

                let input = region.assign_advice(
                    || "input",
                    self.config.input,
                    0,
                    || Value::known(input),
                )?;
                let input = input.value_field();
                let input_cubed = input * input * input;
                let quotient = input_cubed.and_then(|input_cubed| {
                    Value::known(integer_division(input_cubed.evaluate(), BigUint::from(p)))
                });
                let remainder = input_cubed - quotient * Value::known(F::from(p));

                let msb = remainder.and_then(|remainder| {
                    Value::known(integer_division(
                        remainder.evaluate(),
                        BigUint::from(1u8) << l,
                    ))
                });
                let hash = remainder - msb * Value::known(F::from(1 << l));

                region.assign_advice(|| "quotient", self.config.quotient, 0, || quotient)?;
                region.assign_advice(|| "remainder", self.config.remainder, 0, || remainder)?;
                region.assign_advice(|| "msb", self.config.msb, 0, || msb)?;
                region.assign_advice(|| "hash", self.config.hash, 0, || hash.evaluate())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        pasta::{group::ff::PrimeField, Fp},
        plonk::{Circuit, Column, Instance},
    };

    use super::{HashChip, HashConfig, HashFunctionConfig, HashInstructions};

    #[derive(Default)]
    struct MyCircuit<F: PrimeField> {
        input: u64,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct Config {
        hash_config: HashConfig,
        instance: Column<Instance>,
    }

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let input = meta.advice_column();
            let quotient = meta.advice_column();
            let remainder = meta.advice_column();
            let msb = meta.advice_column();
            let hash = meta.advice_column();

            let instance = meta.instance_column();

            meta.enable_equality(instance);
            meta.enable_equality(input);
            meta.enable_equality(hash);

            let hash_function_config = HashFunctionConfig { p: 11, l: 3 };

            Config {
                hash_config: HashChip::configure(
                    meta,
                    input,
                    quotient,
                    remainder,
                    msb,
                    hash,
                    hash_function_config,
                ),
                instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let hash_chip = HashChip::construct(config.hash_config);
            let hash_value =
                hash_chip.hash(&mut layouter.namespace(|| "hash"), F::from(self.input))?;

            layouter.constrain_instance(hash_value.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    #[test]
    fn test_2() {
        let k = 4;
        let circuit = MyCircuit::<Fp> {
            input: 2,
            _marker: PhantomData,
        };
        // (2^3 % 11) % 8 = 0
        let output = Fp::from(0);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_4() {
        let k = 4;
        let circuit = MyCircuit::<Fp> {
            input: 4,
            _marker: PhantomData,
        };
        // (4^3 % 11) % 8 = 1
        let output = Fp::from(1);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_42() {
        let k = 4;
        let circuit = MyCircuit::<Fp> {
            input: 42,
            _marker: PhantomData,
        };
        // (42^3 % 11) % 8 = 3
        let output = Fp::from(3);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn plot() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("hash-layout.png", (512, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Hash Chip Layout", ("sans-serif", 60)).unwrap();

        let circuit = MyCircuit::<Fp> {
            input: 42,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(4, &circuit, &root)
            .unwrap();
    }
}

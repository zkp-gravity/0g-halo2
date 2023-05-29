use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use num_bigint::BigUint;

use crate::utils::integer_division;

use super::range_check::RangeCheckConfig;

pub trait HashInstructions<F: PrimeFieldBits> {
    fn hash(
        &self,
        layouter: impl Layouter<F>,
        input: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub struct HashFunctionConfig {
    /// Prime to use in the hash function.
    pub p: u64,
    /// number of bits for the hash function output.
    /// This has to be one less than the number of bits needed to represent `p`.
    pub l: usize,
    /// Number of input bits.
    pub n_bits: usize,
}

#[derive(Debug, Clone)]
pub struct HashConfig<F: PrimeFieldBits> {
    selector: Selector,
    input: Column<Advice>,
    quotient: Column<Advice>,
    remainder: Column<Advice>,
    msb: Column<Advice>,
    hash: Column<Advice>,
    range_check_config: RangeCheckConfig<F>,
    pub hash_function_config: HashFunctionConfig,
}

/// Implements the "MishMash" hash function: `h(x) = (x^3 % p) % 2^l`.
///
/// Parameters for the hash function are specified in [`HashFunctionConfig`].
///
/// The layout is as follows:
///
/// | input    | quotient | remainder | msb              | hash            |
/// |----------|----------|-----------|------------------|-----------------|
/// | x (copy) | x^3 // p | x^3 % p   | (x^3 % p) // 2^l | (x^3 % p) % 2^l |
///
/// The following constraints are checked:
/// - `x^3 = quotient * p + remainder`
/// - `remainder = msb * 2^l + hash`
/// - `quotient` is in [0, 2^(3 * n_bits - l))
/// - `msb` is in 0 or 1
/// - `remainder` is in [0, p)
///
/// Note that `x` is **not** range-checked. This is assumed to happen
/// elsewhere in the circuit.
/// Also note that the `hash` column is not range-checked to be in [0, 2^l).
/// This is assumed to happen elsewhere in the circuit.
#[derive(Debug, Clone)]
pub struct HashChip<F: PrimeFieldBits> {
    config: HashConfig<F>,
}

impl<F: PrimeFieldBits> HashChip<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        input: Column<Advice>,
        quotient: Column<Advice>,
        remainder: Column<Advice>,
        msb: Column<Advice>,
        hash: Column<Advice>,
        range_check_config: RangeCheckConfig<F>,
        hash_function_config: HashFunctionConfig,
    ) -> HashConfig<F> {
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
            range_check_config,
            hash_function_config,
        }
    }

    pub fn construct(config: HashConfig<F>) -> Self {
        if (config.hash_function_config.n_bits * 3) as u32 > F::CAPACITY {
            panic!("Field too small to store x^3!");
        }
        HashChip { config }
    }

    #[allow(clippy::type_complexity)]
    fn compute_hash(
        &self,
        mut layouter: impl Layouter<F>,
        input: AssignedCell<F, F>,
    ) -> Result<
        (
            AssignedCell<F, F>,
            AssignedCell<F, F>,
            AssignedCell<F, F>,
            AssignedCell<F, F>,
            AssignedCell<F, F>,
        ),
        Error,
    > {
        let p = self.config.hash_function_config.p;
        let l = self.config.hash_function_config.l;
        layouter.assign_region(
            || "hash",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let input_cell =
                    input.copy_advice(|| "input", &mut region, self.config.input, 0)?;
                let input = input_cell.value_field().evaluate();
                let input_cubed = input * input * input;
                let quotient = input_cubed.and_then(|input_cubed| {
                    Value::known(integer_division(input_cubed, BigUint::from(p)))
                });
                let remainder = input_cubed - quotient * Value::known(F::from(p));

                let msb = remainder.and_then(|remainder| {
                    Value::known(integer_division(remainder, BigUint::from(1u8) << l))
                });
                let hash = remainder - msb * Value::known(F::from(1 << l));

                Ok((
                    input_cell,
                    region.assign_advice(|| "quotient", self.config.quotient, 0, || quotient)?,
                    region.assign_advice(|| "remainder", self.config.remainder, 0, || remainder)?,
                    region.assign_advice(|| "msb", self.config.msb, 0, || msb)?,
                    region.assign_advice(|| "hash", self.config.hash, 0, || hash)?,
                ))
            },
        )
    }
}

impl<F: PrimeFieldBits> HashInstructions<F> for HashChip<F> {
    fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        input: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let (_input, quotient, remainder, msb, output) =
            self.compute_hash(layouter.namespace(|| "hash"), input)?;

        let HashFunctionConfig { p, l, n_bits } = self.config.hash_function_config;

        // Check that all cells have the right number of bits, with three exceptions:
        // - The input is assumed to already be range-checked
        // - output should be l bits, but it's later decomposed and used in a table lookup, which enforces the range
        // - remainder should be l + 1 bits, but does not need to be range-checked, because we verify that r = 2^l * msb + output
        self.config.range_check_config.range_check(
            layouter.namespace(|| "range check quotient"),
            quotient,
            n_bits * 3 - l,
        )?;
        self.config.range_check_config.range_check(
            layouter.namespace(|| "range check msb"),
            msb,
            1,
        )?;

        // Additionally, we have to check that remainder < p
        self.config.range_check_config.le_constant(
            layouter.namespace(|| "remainder < p"),
            remainder,
            F::from(p - 1),
        )?;

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ff::PrimeFieldBits;
    use halo2_proofs::circuit::Value;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit, Column, Instance, TableColumn},
    };

    use crate::gadgets::range_check::{load_bytes_column, RangeCheckConfig};

    use super::{HashChip, HashConfig, HashFunctionConfig, HashInstructions};

    #[derive(Default)]
    struct MyCircuit<F: PrimeFieldBits> {
        input: u64,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct Config<F: PrimeFieldBits> {
        hash_config: HashConfig<F>,
        table_column: TableColumn,
        instance: Column<Instance>,
    }

    impl<F: PrimeFieldBits> Circuit<F> for MyCircuit<F> {
        type Config = Config<F>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let input = meta.advice_column();
            let quotient = meta.advice_column();
            let remainder = meta.advice_column();
            let msb = meta.advice_column();
            let hash = meta.advice_column();

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let instance = meta.instance_column();

            meta.enable_equality(instance);
            meta.enable_equality(input);
            meta.enable_equality(quotient);
            meta.enable_equality(remainder);
            meta.enable_equality(msb);
            meta.enable_equality(hash);

            let hash_function_config = HashFunctionConfig {
                p: 11,
                l: 3,
                n_bits: 8,
            };

            let table_column = meta.lookup_table_column();
            let lookup_range_check = RangeCheckConfig::configure(meta, input, table_column);

            Config {
                hash_config: HashChip::configure(
                    meta,
                    input,
                    quotient,
                    remainder,
                    msb,
                    hash,
                    lookup_range_check,
                    hash_function_config,
                ),
                table_column,
                instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let assigned_input = layouter.assign_region(
                || "input",
                |mut region| {
                    region.assign_advice(
                        || "input",
                        config.hash_config.input,
                        0,
                        || Value::known(F::from(self.input)),
                    )
                },
            )?;

            load_bytes_column(&mut layouter, config.table_column)?;
            let hash_chip = HashChip::construct(config.hash_config);
            let hash_value = hash_chip.hash(layouter.namespace(|| "hash"), assigned_input)?;

            layouter.constrain_instance(hash_value.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    #[test]
    fn test_2() {
        let k = 9;
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
        let k = 9;
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
        let k = 9;
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
    fn test_255() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            input: 255,
            _marker: PhantomData,
        };
        // (255^3 % 11) % 8 = 0
        let output = Fp::from(0);
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
            .render(5, &circuit, &root)
            .unwrap();
    }
}

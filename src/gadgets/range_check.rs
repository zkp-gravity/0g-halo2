use ff::PrimeFieldBits;
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector, TableColumn},
    poly::Rotation,
};

const K: usize = 8;

/// A wrapper around [`LookupRangeCheckConfig`] which uses `K = 8`, i.e., 8 bits per word.
/// It can check for an arbitrary number of bits and implements a less-or-equal check.
/// 
/// It uses a single advice column.
#[derive(Clone, Debug)]
pub struct RangeCheckConfig<F: PrimeFieldBits> {
    range_check_config: LookupRangeCheckConfig<F, K>,
    advice_column: Column<Advice>,
    le_selector: Selector,
}

impl<F: PrimeFieldBits> RangeCheckConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_column: Column<Advice>,
        byte_column: TableColumn,
    ) -> Self {
        let range_check_config =
            LookupRangeCheckConfig::configure(meta, advice_column, byte_column);

        let le_selector = meta.selector();
        meta.create_gate("le", |meta| {
            // The prover has to provide a diff s.t. x + diff = y
            let le_selector = meta.query_selector(le_selector);

            let x = meta.query_advice(advice_column, Rotation::prev());
            let y = meta.query_advice(advice_column, Rotation::cur());
            let diff = meta.query_advice(advice_column, Rotation::next());

            Constraints::with_selector(le_selector, vec![x + diff - y])
        });

        Self {
            range_check_config,
            advice_column,
            le_selector,
        }
    }

    /// Check that `x <= y`, where `y` is a constant.
    /// It assumes that `x` is already checked to have the right number of bits (,i.e., at most as many as `y`).
    pub fn le_constant(
        &self,
        mut layouter: impl Layouter<F>,
        x: AssignedCell<F, F>,
        y: F,
    ) -> Result<(), Error> {
        let diff_cell = layouter.assign_region(
            || "le",
            |mut region| {
                let diff = x.value().map(|x| y - *x);

                x.copy_advice(|| "x", &mut region, self.advice_column, 0)?;
                region.assign_advice_from_constant(|| "y", self.advice_column, 1, y)?;
                let diff_cell = region.assign_advice(|| "diff", self.advice_column, 2, || diff)?;
                self.le_selector.enable(&mut region, 1)?;
                Ok(diff_cell)
            },
        )?;

        let y_bits = y.to_le_bits();
        let n_bits = y_bits.len() - y_bits.trailing_zeros();

        self.range_check(layouter, diff_cell, n_bits)?;

        Ok(())
    }

    /// Check that the given input is in the range [0, 2^n_bits).
    /// It first decomposes the input into bytes and then performs a "short" range check on the last byte.
    pub fn range_check(
        &self,
        mut layouter: impl Layouter<F>,
        input: AssignedCell<F, F>,
        n_bits: usize,
    ) -> Result<(), Error> {
        let words = n_bits / K;
        let last_word = {
            if words > 0 {
                let running_sum = self.range_check_config.copy_check(
                    layouter.namespace(|| "range check (words)"),
                    input,
                    words,
                    // If n_bits is divisible by K, the last word is enforced to be zero and we can skip the short range check!
                    n_bits % K == 0,
                )?;
                running_sum[running_sum.len() - 1].clone()
            } else {
                input
            }
        };
        if n_bits % K != 0 {
            // If n_bits is not divisible by K, the last word should be of (n_bits % K) bits
            self.range_check_config.copy_short_check(
                layouter.namespace(|| "range check (short)"),
                last_word,
                n_bits % K,
            )?;
        }
        Ok(())
    }

    /// Fill a table column with bytes.
    /// This is only needed if there isn't already a table with all byte values.
    pub fn load_bytes_column(
        layouter: &mut impl Layouter<F>,
        table_column: TableColumn,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "table_idx",
            |mut table| {
                for index in 0..(1 << K) {
                    table.assign_cell(
                        || "table_idx",
                        table_column,
                        index,
                        || Value::known(F::from(index as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ff::PrimeFieldBits;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, TableColumn},
    };

    use super::RangeCheckConfig;

    /// Checks that `x <= y`, where `y` is a constant.
    #[derive(Default)]
    struct MyCircuit<F: PrimeFieldBits> {
        x: u64,
        y: u64,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct Config<F: PrimeFieldBits> {
        range_check_config: RangeCheckConfig<F>,
        advice_column: Column<Advice>,
        table_column: TableColumn,
    }

    impl<F: PrimeFieldBits> Circuit<F> for MyCircuit<F> {
        type Config = Config<F>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let advice_column = meta.advice_column();
            let table_column = meta.lookup_table_column();
            let constants = meta.fixed_column();

            meta.enable_equality(advice_column);
            meta.enable_constant(constants);

            let range_check_config = RangeCheckConfig::configure(meta, advice_column, table_column);

            Config {
                range_check_config,
                advice_column,
                table_column,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let x_cell = layouter.assign_region(
                || "x",
                |mut region| {
                    region.assign_advice(
                        || "x",
                        config.advice_column,
                        0,
                        || Value::known(F::from(self.x)),
                    )
                },
            )?;
            RangeCheckConfig::load_bytes_column(&mut layouter, config.table_column)?;
            config
                .range_check_config
                .le_constant(layouter, x_cell, F::from(self.y))?;
            Ok(())
        }
    }

    #[test]
    fn test_le_equal() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            x: 1023,
            y: 1023,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_le_less() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            x: 1022,
            y: 1023,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_le_greater() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            x: 1024,
            y: 1023,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn plot() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("le-layout.png", (512, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Less or Equal Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp> {
            x: 1023,
            y: 1023,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(5, &circuit, &root)
            .unwrap();
    }
}

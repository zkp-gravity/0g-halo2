use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector, TableColumn,
    },
    poly::Rotation,
};

use crate::utils::to_u32;

pub trait GreaterThanInstructions<F: PrimeFieldBits> {
    /// Computes whether `x > y` by witnessing `x` and treating `y` as a constant.
    /// Note that both `x` and `y` are assumed to be bytes (on `x`, this is enforced; `y` us a public constant).
    /// Returns the assigned cell for `x` and the result (0 or 1).
    fn greater_than_witness(
        &self,
        layouter: &mut impl Layouter<F>,
        x: F,
        y: F,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error>;

    /// Computes whether `x > y` by copying `x` from an existing cell and treating `y` as a constant.
    /// Note that both `x` and `y` are assumed to be bytes (on `x`, this is enforced; `y` us a public constant).
    /// Returns the assigned cell with the result (0 or 1).
    fn greater_than_copy(
        &self,
        layouter: &mut impl Layouter<F>,
        x: &AssignedCell<F, F>,
        y: F,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub struct GreaterThanChipConfig {
    x: Column<Advice>,
    y: Column<Advice>,
    diff: Column<Advice>,
    is_gt: Column<Advice>,
    selector: Selector,
}

#[derive(Debug, Clone)]
pub struct GreaterThanChip<F: PrimeFieldBits> {
    config: GreaterThanChipConfig,
    _marker: PhantomData<F>,
}

/// Implements greater-than.
///
/// The layout is as follows:
/// | x                   | y            | diff                | is_gt |
/// |---------------------|--------------|---------------------|-------|
/// | b (copy or witness) | t (constant) | 256 * is_gt + t - b | b > t |
///
/// The following constraints are enforced:
/// - x is a byte (via a lookup table)
/// - diff is a byte (via a lookup table)
/// - is_gt is a bit
/// - x + diff = 256 * is_gt + y
impl<F: PrimeFieldBits> GreaterThanChip<F> {
    pub fn construct(config: GreaterThanChipConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        x: Column<Advice>,
        y: Column<Advice>,
        diff: Column<Advice>,
        is_gt: Column<Advice>,
        byte_column: TableColumn,
    ) -> GreaterThanChipConfig {
        let selector = meta.complex_selector();

        meta.lookup("x is byte", |meta| {
            let selector = meta.query_selector(selector);

            let x = meta.query_advice(x, Rotation::cur());

            vec![(selector * x, byte_column)]
        });

        meta.lookup("diff is byte", |meta| {
            let selector = meta.query_selector(selector);

            let diff = meta.query_advice(diff, Rotation::cur());

            vec![(selector * diff, byte_column)]
        });

        meta.create_gate("is_gt is bit", |meta| {
            let selector = meta.query_selector(selector);

            let is_gt = meta.query_advice(is_gt, Rotation::cur());

            Constraints::with_selector(
                selector,
                vec![is_gt.clone() * (is_gt - Expression::Constant(F::ONE))],
            )
        });

        meta.create_gate("x + diff = 256 * is_gt + y", |meta| {
            let selector = meta.query_selector(selector);

            let x = meta.query_advice(x, Rotation::cur());
            let y = meta.query_advice(y, Rotation::cur());
            let diff = meta.query_advice(diff, Rotation::cur());
            let is_gt = meta.query_advice(is_gt, Rotation::cur());

            let two_pow_8 = Expression::Constant(F::from(256u64));

            Constraints::with_selector(selector, vec![x + diff - is_gt * two_pow_8 - y])
        });

        GreaterThanChipConfig {
            x,
            y,
            diff,
            is_gt,
            selector,
        }
    }

    fn greater_than(
        &self,
        region: &mut Region<F>,
        x: &AssignedCell<F, F>,
        y: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        if to_u32(&y) > 255 {
            panic!("y must be less than 256!");
        }

        let greater_than = x.value().map(|x| F::from((to_u32(x) > to_u32(&y)) as u64));
        // x + diff = 256 * is_gt + y
        // -> diff = 256 * is_gt + y - x
        let diff = x
            .value()
            .zip(greater_than)
            .map(|(x, gt)| F::from(256u64) * gt + y - x);

        self.config.selector.enable(region, 0)?;

        region.assign_advice_from_constant(|| "y", self.config.y, 0, y)?;
        region.assign_advice(|| "diff", self.config.diff, 0, || diff)?;
        region.assign_advice(|| "gt", self.config.is_gt, 0, || greater_than)
    }
}

impl<F: PrimeFieldBits> GreaterThanInstructions<F> for GreaterThanChip<F> {
    fn greater_than_witness(
        &self,
        layouter: &mut impl Layouter<F>,
        x: F,
        y: F,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        layouter.assign_region(
            || "greater_than_witness",
            |mut region| {
                let x_cell = region.assign_advice(|| "x", self.config.x, 0, || Value::known(x))?;
                let result_cell = self.greater_than(&mut region, &x_cell, y)?;
                Ok((x_cell, result_cell))
            },
        )
    }

    fn greater_than_copy(
        &self,
        layouter: &mut impl Layouter<F>,
        x: &AssignedCell<F, F>,
        y: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "greater_than_copy",
            |mut region| {
                let x_cell = x.copy_advice(|| "x", &mut region, self.config.x, 0)?;
                self.greater_than(&mut region, &x_cell, y)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ff::{Field, PrimeFieldBits};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance, TableColumn},
    };

    use crate::gadgets::range_check::RangeCheckConfig;

    use super::{GreaterThanChip, GreaterThanChipConfig, GreaterThanInstructions};

    /// Checks whether `x > y`, where `y` is a constant.
    #[derive(Default)]
    struct MyCircuit<F: PrimeFieldBits> {
        x: u64,
        y: u64,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct Config {
        greater_than_config: GreaterThanChipConfig,
        table_column: TableColumn,
        instance: Column<Instance>,
    }

    impl<F: PrimeFieldBits> Circuit<F> for MyCircuit<F> {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let x = meta.advice_column();
            let y = meta.advice_column();
            let diff = meta.advice_column();
            let is_gt = meta.advice_column();

            let table_column = meta.lookup_table_column();
            let constants = meta.fixed_column();
            let instance = meta.instance_column();

            meta.enable_equality(x);
            meta.enable_equality(y);
            meta.enable_equality(is_gt);
            meta.enable_equality(instance);
            meta.enable_constant(constants);

            let range_check_config =
                GreaterThanChip::configure(meta, x, y, diff, is_gt, table_column);

            Config {
                greater_than_config: range_check_config,
                table_column,
                instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            RangeCheckConfig::load_bytes_column(&mut layouter, config.table_column)?;
            let greater_than_chip = GreaterThanChip::construct(config.greater_than_config);
            let (_, result) = greater_than_chip.greater_than_witness(
                &mut layouter,
                F::from(self.x),
                F::from(self.y),
            )?;

            layouter.constrain_instance(result.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    #[test]
    fn test_gt_true() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            x: 129,
            y: 64,
            _marker: PhantomData,
        };
        let output = Fp::ONE;
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_gt_false() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            x: 64,
            y: 129,
            _marker: PhantomData,
        };
        let output = Fp::ZERO;
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_gt_equal() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            x: 64,
            y: 64,
            _marker: PhantomData,
        };
        let output = Fp::ZERO;
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_x_too_large() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            x: 256,
            y: 64,
            _marker: PhantomData,
        };
        let output = Fp::ZERO;
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn plot() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("gt-layout.png", (512, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Greater Than Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp> {
            x: 129,
            y: 64,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(5, &circuit, &root)
            .unwrap();
    }
}

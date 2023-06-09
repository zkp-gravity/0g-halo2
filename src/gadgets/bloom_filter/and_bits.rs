use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};

/// Interface of the And Bits gadget.
pub trait AndBitsInstruction<F: PrimeField> {
    /// Performs the AND operation on the bits.
    fn and_bits(
        &self,
        layouter: &mut impl Layouter<F>,
        bits: Vec<AssignedCell<F, F>>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Clone, Debug)]
pub struct AndBitsChipConfig {
    bits: Column<Advice>,
    acc: Column<Advice>,
    selector: Selector,
}

/// Implements an and-reduction using two advice columns.
///
/// The layout is as follows:
///
/// | bits | acc   |
/// |------|-------|
/// | b_1  | 1     |
/// | b_2  | acc_1 |
/// | ...  | acc_2 |
/// | b_n  | ...   |
/// |      | acc_n |
pub struct AndBitsChip<F: PrimeField> {
    config: AndBitsChipConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> AndBitsChip<F> {
    /// Constructs a new instance of the And Bits gadget.
    pub fn construct(config: AndBitsChipConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bits: Column<Advice>,
        acc: Column<Advice>,
    ) -> AndBitsChipConfig {
        let selector = meta.selector();

        meta.create_gate("validate_bit_acc", |meta| {
            // Layout:
            // | bits | acc      | selector |
            // |------|----------|----------|
            // | bit  | acc_cur  | 1        |
            // |      | acc_next |          |
            let selector = meta.query_selector(selector);

            let bit = meta.query_advice(bits, Rotation::cur());
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let acc_next = meta.query_advice(acc, Rotation::next());

            Constraints::with_selector(selector, vec![acc_cur * bit - acc_next])
        });

        AndBitsChipConfig {
            bits,
            acc,
            selector,
        }
    }
}

impl<F: PrimeField> AndBitsInstruction<F> for AndBitsChip<F> {
    fn and_bits(
        &self,
        layouter: &mut impl Layouter<F>,
        bits: Vec<AssignedCell<F, F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "and bits",
            |mut region| {
                let bit_values = bits
                    .iter()
                    .map(|bit_cell| bit_cell.value_field().evaluate())
                    .collect::<Vec<_>>();

                let mut acc_values = vec![Value::known(F::ONE)];
                for (i, bit_value) in bit_values.iter().enumerate() {
                    let prev_value = acc_values[i];
                    let acc_value = prev_value.zip(*bit_value).map(|(prev, bit)| prev * bit);
                    acc_values.push(acc_value);
                }

                for (i, bit) in bits.iter().enumerate() {
                    bit.copy_advice(|| "bit", &mut region, self.config.bits, i)?;
                }

                // Using assign_advice_from_constant() instead of assign_advice()
                // with acc_values[0] has a side effect of adding an equality constraint.
                let mut cell = region.assign_advice_from_constant(
                    || "acc_first",
                    self.config.acc,
                    0,
                    F::ONE,
                )?;
                for (i, acc_value) in acc_values.into_iter().enumerate().skip(1) {
                    cell = region.assign_advice(|| "acc", self.config.acc, i, || acc_value)?;
                    self.config.selector.enable(&mut region, i - 1)?;
                }
                Ok(cell)
            },
        )
    }
}

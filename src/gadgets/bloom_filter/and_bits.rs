use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};

pub trait AndBitsInstruction<F: PrimeField> {
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

pub struct AndBitsChip<F: PrimeField> {
    config: AndBitsChipConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> AndBitsChip<F> {
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

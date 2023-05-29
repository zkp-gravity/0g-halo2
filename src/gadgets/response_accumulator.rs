use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};

pub trait ResponseAccumulatorInstructions<F: PrimeField> {
    fn accumulate_responses(
        &self,
        layouter: &mut impl Layouter<F>,
        responses: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub struct ResponseAccumulatorChipConfig {
    advice_columns: [Column<Advice>; 5],
    selector: Selector,
}

#[derive(Debug, Clone)]
pub struct ResponseAccumulatorChip<F: PrimeField> {
    config: ResponseAccumulatorChipConfig,
    _marker: PhantomData<F>,
}

/// Accumulates responses by summing them up.
///
/// The layout is as follows (example with 7 values):
///
/// | a1 | a2 | a3 | a4           | acc            |
/// |----|----|----|--------------|----------------|
/// | b1 | b2 | b3 | b4           | 0 (constant)   |
/// | b5 | b6 | b7 | 0 (constant) | acc_1          |
/// |    |    |    |              | acc_2 (result) |
///
/// The gadget enforces that: `acc[i + 1] = acc[i] + a1[i] + a2[i] + a3[i] + a4[i]`.
impl<F: PrimeField> ResponseAccumulatorChip<F> {
    pub fn construct(config: ResponseAccumulatorChipConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_columns: [Column<Advice>; 5],
    ) -> ResponseAccumulatorChipConfig {
        let selector = meta.selector();

        meta.create_gate("accumulate_responses", |meta| {
            let selector = meta.query_selector(selector);

            let x1 = meta.query_advice(advice_columns[0], Rotation::cur());
            let x2 = meta.query_advice(advice_columns[1], Rotation::cur());
            let x3 = meta.query_advice(advice_columns[2], Rotation::cur());
            let x4 = meta.query_advice(advice_columns[3], Rotation::cur());

            let prev_acc = meta.query_advice(advice_columns[4], Rotation::cur());
            let acc = meta.query_advice(advice_columns[4], Rotation::next());

            Constraints::with_selector(selector, vec![x1 + x2 + x3 + x4 + prev_acc - acc])
        });

        ResponseAccumulatorChipConfig {
            advice_columns,
            selector,
        }
    }
}

impl<F: PrimeField> ResponseAccumulatorInstructions<F> for ResponseAccumulatorChip<F> {
    fn accumulate_responses(
        &self,
        layouter: &mut impl Layouter<F>,
        responses: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "accumulate_responses",
            |mut region| {
                let row_sums = responses
                    .chunks(4)
                    .map(|row| {
                        row.iter()
                            .map(|cell| cell.value())
                            .fold(Value::known(F::ZERO), |acc, v| acc + v)
                    })
                    .collect::<Vec<_>>();

                let mut acc_cell = region.assign_advice_from_constant(
                    || "acc 0",
                    self.config.advice_columns[4],
                    0,
                    F::ZERO,
                )?;
                let mut current_acc_value = Value::known(F::ZERO);
                for (row_index, cur_row_sum) in row_sums.iter().enumerate() {
                    self.config.selector.enable(&mut region, row_index)?;
                    for i in 0..4 {
                        let index = row_index * 4 + i;
                        if index < responses.len() {
                            responses[index].copy_advice(
                                || format!("response {i}"),
                                &mut region,
                                self.config.advice_columns[i],
                                row_index,
                            )?;
                        } else {
                            region.assign_advice_from_constant(
                                || "dummy response",
                                self.config.advice_columns[i],
                                row_index,
                                F::ZERO,
                            )?;
                        }
                    }
                    current_acc_value = current_acc_value + cur_row_sum;
                    acc_cell = region.assign_advice(
                        || format!("acc {}", row_index + 1),
                        self.config.advice_columns[4],
                        row_index + 1,
                        || current_acc_value,
                    )?;
                }

                Ok(acc_cell)
            },
        )
    }
}

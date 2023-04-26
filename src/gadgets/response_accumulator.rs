use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};

pub(crate) trait ResponseAccumulatorInstructions<F: FieldExt> {
    fn accumulate_responses(
        &self,
        layouter: &mut impl Layouter<F>,
        responses: &Vec<AssignedCell<F, F>>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub(crate) struct ResponseAccumulatorChipConfig {
    advice_columns: [Column<Advice>; 5],
    selector: Selector,
}

#[derive(Debug, Clone)]
pub(crate) struct ResponseAccumulatorChip<F: FieldExt> {
    config: ResponseAccumulatorChipConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ResponseAccumulatorChip<F> {
    pub(crate) fn construct(config: ResponseAccumulatorChipConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub(crate) fn configure(
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

impl<F: FieldExt> ResponseAccumulatorInstructions<F> for ResponseAccumulatorChip<F> {
    fn accumulate_responses(
        &self,
        layouter: &mut impl Layouter<F>,
        responses: &Vec<AssignedCell<F, F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "accumulate_responses",
            |mut region| {
                let n_rows = (responses.len() + 3) / 4;

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
                for row_index in 0..n_rows {
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
                    current_acc_value = current_acc_value + row_sums[row_index];
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

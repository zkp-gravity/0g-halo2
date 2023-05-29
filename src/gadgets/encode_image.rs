use std::collections::BTreeMap;

use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, TableColumn},
};
use ndarray::{Array2, Array3};

use crate::gadgets::greater_than::GreaterThanWitnessResult;

use super::greater_than::{GreaterThanChip, GreaterThanChipConfig, GreaterThanInstructions};

pub trait EncodeImageInstructions<F: PrimeFieldBits> {
    /// Maps an image to a bit string.
    fn encode_image(
        &self,
        layouter: impl Layouter<F>,
        image: &Array2<u8>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error>;
}

#[derive(Clone, Debug)]
pub struct EncodeImageChipConfig {
    advice_column: Column<Advice>,
    greater_than_chip_config: GreaterThanChipConfig,
}

/// Encodes an image into a bit string, as follows:
/// - Each pixel intensity is passed to [`GreaterThanChip`] for each threshold.
///   This also range-checks the intensity to make sure it's in the range [0, 255].
///   - As a special case, if the threshold is 0, a constant "1" is returned
///     (as the intensity is always greater than 1).
/// - Intensities belonging to the same pixel are constrained to be equal.
pub struct EncodeImageChip<F: PrimeFieldBits> {
    greater_than_chip: GreaterThanChip<F>,
    config: EncodeImageChipConfig,
    binarization_thresholds: Array3<u16>,
}

impl<F: PrimeFieldBits> EncodeImageChip<F> {
    pub fn construct(config: EncodeImageChipConfig, binarization_thresholds: Array3<u16>) -> Self {
        let greater_than_chip = GreaterThanChip::construct(config.greater_than_chip_config.clone());
        Self {
            greater_than_chip,
            config,
            binarization_thresholds,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        x: Column<Advice>,
        y: Column<Advice>,
        diff: Column<Advice>,
        is_gt: Column<Advice>,
        byte_column: TableColumn,
    ) -> EncodeImageChipConfig {
        let greater_than_chip_config =
            GreaterThanChip::configure(meta, x, y, diff, is_gt, byte_column);
        EncodeImageChipConfig {
            advice_column: is_gt,
            greater_than_chip_config,
        }
    }
}

impl<F: PrimeFieldBits> EncodeImageInstructions<F> for EncodeImageChip<F> {
    fn encode_image(
        &self,
        mut layouter: impl Layouter<F>,
        image: &Array2<u8>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let (width, height) = (image.shape()[0], image.shape()[1]);

        let mut intensity_cells: BTreeMap<(usize, usize), AssignedCell<F, F>> = BTreeMap::new();
        let mut bit_cells = vec![];

        for b in 0..self.binarization_thresholds.shape()[2] {
            for i in 0..width {
                for j in 0..height {
                    let threshold = self.binarization_thresholds[(i, j, b)];
                    assert!(threshold <= 256);

                    let bit_cell = if threshold == 0 {
                        // If the threshold is zero, the bit is always one, regardless of the of the intensity.
                        // Unfortunately, this has to be handled separately, as the greater than gadget can't
                        // handle a threshold of -1 (see below).
                        layouter.assign_region(
                            || "bit is one",
                            |mut region| {
                                region.assign_advice_from_constant(
                                    || "gt",
                                    self.config.advice_column,
                                    0,
                                    F::ONE,
                                )
                            },
                        )?
                    } else {
                        // The result should be true if the intensity is greater or equal than the threshold,
                        // but the gadget only implements greater than, so we need to subtract 1 from the threshold.
                        // Because we already handled the threshold == 0 case, this means that `t` is now in the
                        // range [0, 255], which is required by the greater than gadget.
                        let t = F::from((self.binarization_thresholds[(i, j, b)] - 1) as u64);

                        match intensity_cells.get(&(i, j)) {
                            None => {
                                // For the first cell, we want to remember the intensity cell, so that we can
                                // add a copy constraint for the other thresholds.
                                let GreaterThanWitnessResult { x_cell, gt_cell } =
                                    self.greater_than_chip.greater_than_witness(
                                        &mut layouter,
                                        F::from(image[(i, j)] as u64),
                                        t,
                                    )?;
                                intensity_cells.insert((i, j), x_cell);
                                gt_cell
                            }
                            Some(first_cell) => {
                                // For the other cells, we want to add a copy constraint to the first cell.
                                self.greater_than_chip.greater_than_copy(
                                    &mut layouter,
                                    first_cell,
                                    t,
                                )?
                            }
                        }
                    };
                    bit_cells.push(bit_cell);
                }
            }
        }
        Ok(bit_cells)
    }
}

use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};

use crate::utils::{to_be_bits, to_u32};

/// The interface of the Bit Selector gadget.
pub trait BitSelectorInstructions<F: PrimeFieldBits> {
    /// Given a byte and index, returns the bit at the given index
    /// (assuming a big-endian representation).
    fn select_bit(
        &self,
        layouter: &mut impl Layouter<F>,
        byte: AssignedCell<F, F>,
        index: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Clone, Debug)]
pub struct BitSelectorChipConfig {
    byte: Column<Advice>,
    index: Column<Advice>,
    bit: Column<Advice>,

    /// Column of all bytes (not unique). Public so that it can be reused by other gadgets.
    pub byte_column: TableColumn,
    index_column: TableColumn,
    bit_column: TableColumn,

    lookup_selector: Selector,
}

/// Implements a bit selector using a lookup table.
/// The layout is a single row with a `(byte, index, bit)` tuple.
/// Note that this implicitly range-checks `index` to be in `[0, 8)`.
pub struct BitSelectorChip<F: PrimeFieldBits> {
    config: BitSelectorChipConfig,

    _marker: PhantomData<F>,
}

impl<F: PrimeFieldBits> BitSelectorChip<F> {
    pub fn construct(config: BitSelectorChipConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    /// Loads the lookup table.
    /// Should be called before [`BitSelectorInstructions::select_bit``].
    pub fn load(&mut self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "byte,index,bit",
            |mut table| {
                let mut table_index = 0;
                for b in 0..(1 << 8) {
                    for i in 0..8 {
                        let bit = if b & (1 << (7 - i)) == 0 {
                            F::ZERO
                        } else {
                            F::ONE
                        };

                        table.assign_cell(
                            || "byte",
                            self.config.byte_column,
                            table_index,
                            || Value::known(F::from(b as u64)),
                        )?;
                        table.assign_cell(
                            || "index",
                            self.config.index_column,
                            table_index,
                            || Value::known(F::from(i as u64)),
                        )?;
                        table.assign_cell(
                            || "bit",
                            self.config.bit_column,
                            table_index,
                            || Value::known(bit),
                        )?;

                        table_index += 1;
                    }
                }
                Ok(())
            },
        )
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        byte: Column<Advice>,
        index: Column<Advice>,
        bit: Column<Advice>,
    ) -> BitSelectorChipConfig {
        let lookup_selector = meta.complex_selector();
        let byte_column = meta.lookup_table_column();
        let index_column = meta.lookup_table_column();
        let bit_column = meta.lookup_table_column();

        meta.lookup("bit_lookup", |meta| {
            let lookup_selector = meta.query_selector(lookup_selector);

            let byte = meta.query_advice(byte, Rotation::cur());
            let index = meta.query_advice(index, Rotation::cur());
            let bit = meta.query_advice(bit, Rotation::cur());

            // Note that we don't provide a default value. This is because if the selector
            // is zero, the tuple (0, 0, 0) is looked up, which is already in the table.

            vec![
                (lookup_selector.clone() * byte, byte_column),
                (lookup_selector.clone() * index, index_column),
                (lookup_selector * bit, bit_column),
            ]
        });

        BitSelectorChipConfig {
            byte,
            index,
            bit,
            byte_column,
            index_column,
            bit_column,
            lookup_selector,
        }
    }
}

impl<F: PrimeFieldBits> BitSelectorInstructions<F> for BitSelectorChip<F> {
    fn select_bit(
        &self,
        layouter: &mut impl Layouter<F>,
        byte: AssignedCell<F, F>,
        index: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "select_bit",
            |mut region| {
                let bit = byte.value().zip(index.value()).map(|(byte, index)| {
                    let bits = to_be_bits(byte, 8);
                    let index = to_u32(index) as usize;
                    if bits[index] {
                        F::ONE
                    } else {
                        F::ZERO
                    }
                });

                self.config.lookup_selector.enable(&mut region, 0)?;

                byte.copy_advice(|| "byte", &mut region, self.config.byte, 0)?;
                index.copy_advice(|| "index", &mut region, self.config.index, 0)?;
                region.assign_advice(|| "bit", self.config.bit, 0, || bit)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ff::PrimeFieldBits;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, Column, Instance},
    };

    use super::{BitSelectorChip, BitSelectorChipConfig, BitSelectorInstructions};

    #[derive(Default)]
    struct MyCircuit<F: PrimeFieldBits> {
        byte: u64,
        index: u64,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct Config {
        config: BitSelectorChipConfig,
        instance: Column<Instance>,
    }

    impl<F: PrimeFieldBits> Circuit<F> for MyCircuit<F> {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let byte = meta.advice_column();
            let index = meta.advice_column();
            let bit = meta.advice_column();

            let instance = meta.instance_column();

            meta.enable_equality(instance);
            meta.enable_equality(byte);
            meta.enable_equality(index);
            meta.enable_equality(bit);

            Config {
                config: BitSelectorChip::configure(meta, byte, index, bit),
                instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let (byte_cell, index_cell) = layouter.assign_region(
                || "inputs",
                |mut region| {
                    let byte_cell = region.assign_advice(
                        || "byte",
                        config.config.byte,
                        0,
                        || Value::known(F::from(self.byte)),
                    )?;
                    let index_cell = region.assign_advice(
                        || "index",
                        config.config.index,
                        0,
                        || Value::known(F::from(self.index)),
                    )?;
                    Ok((byte_cell, index_cell))
                },
            )?;

            let mut chip = BitSelectorChip::construct(config.config);
            chip.load(&mut layouter)?;
            let result = chip.select_bit(&mut layouter, byte_cell, index_cell)?;

            layouter.constrain_instance(result.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    #[test]
    fn test_0() {
        let k = 12;
        let circuit = MyCircuit::<Fp> {
            byte: 0b11111110,
            index: 0,
            _marker: PhantomData,
        };
        let output = Fp::from(1);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_1() {
        let k = 12;
        let circuit = MyCircuit::<Fp> {
            byte: 0b11111110,
            index: 1,
            _marker: PhantomData,
        };
        let output = Fp::from(1);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_7() {
        let k = 12;
        let circuit = MyCircuit::<Fp> {
            byte: 0b11111110,
            index: 7,
            _marker: PhantomData,
        };
        let output = Fp::from(0);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn plot() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("bit-selector-layout.png", (512, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Bit Selector Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp> {
            byte: 0b11111110,
            index: 0,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(4, &circuit, &root)
            .unwrap();
    }
}

use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};

use crate::utils::{to_le_bits, to_u32};

pub trait BitSelectorInstructions<F: PrimeField> {
    fn select_bit(
        &self,
        layouter: &mut impl Layouter<F>,
        byte: AssignedCell<F, F>,
        index: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Clone, Debug)]
pub struct BitSelectorConfig {
    byte: Column<Advice>,
    index: Column<Advice>,
    bit: Column<Advice>,

    lookup_selector: Selector,
}

pub struct BitSelectorChip<F: PrimeField> {
    config: BitSelectorConfig,

    _marker: PhantomData<F>,
}

impl<F: PrimeField> BitSelectorChip<F> {
    pub fn construct(config: BitSelectorConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        byte: Column<Advice>,
        index: Column<Advice>,
        bit: Column<Advice>,
        byte_column: TableColumn,
        index_column: TableColumn,
        bit_column: TableColumn,
    ) -> BitSelectorConfig {
        let lookup_selector = meta.complex_selector();

        meta.lookup("bit_lookup", |meta| {
            let lookup_selector = meta.query_selector(lookup_selector);

            let byte = meta.query_advice(byte, Rotation::cur());
            let index = meta.query_advice(index, Rotation::cur());
            let bit = meta.query_advice(bit, Rotation::cur());

            vec![
                (lookup_selector.clone() * byte, byte_column),
                (lookup_selector.clone() * index, index_column),
                (lookup_selector.clone() * bit, bit_column),
            ]
        });

        BitSelectorConfig {
            byte,
            index,
            bit,
            lookup_selector,
        }
    }
}

impl<F: PrimeField> BitSelectorInstructions<F> for BitSelectorChip<F> {
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
                    let bits = to_le_bits(byte, 8);
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

    use ff::PrimeField;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, Column, Instance, TableColumn},
    };

    use super::{BitSelectorChip, BitSelectorConfig, BitSelectorInstructions};

    #[derive(Default)]
    struct MyCircuit<F: PrimeField> {
        byte: u64,
        index: u64,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct Config {
        config: BitSelectorConfig,
        instance: Column<Instance>,
        byte_column: TableColumn,
        index_column: TableColumn,
        bit_column: TableColumn,
    }

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let byte = meta.advice_column();
            let index = meta.advice_column();
            let bit = meta.advice_column();

            let instance = meta.instance_column();
            let byte_column = meta.lookup_table_column();
            let index_column = meta.lookup_table_column();
            let bit_column = meta.lookup_table_column();

            meta.enable_equality(instance);
            meta.enable_equality(byte);
            meta.enable_equality(index);
            meta.enable_equality(bit);

            Config {
                config: BitSelectorChip::configure(
                    meta,
                    byte,
                    index,
                    bit,
                    byte_column,
                    index_column,
                    bit_column,
                ),
                instance,
                byte_column,
                index_column,
                bit_column,
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

            layouter.assign_table(
                || "byte,index,bit",
                |mut table| {
                    let mut table_index = 0;
                    for b in 0..(1 << 8) {
                        for i in 0..8 {
                            let bit = if (b >> i) & 1 == 1 { F::ONE } else { F::ZERO };

                            table.assign_cell(
                                || "byte",
                                config.byte_column,
                                table_index,
                                || Value::known(F::from(b as u64)),
                            )?;
                            table.assign_cell(
                                || "index",
                                config.index_column,
                                table_index,
                                || Value::known(F::from(i as u64)),
                            )?;
                            table.assign_cell(
                                || "bit",
                                config.bit_column,
                                table_index,
                                || Value::known(bit),
                            )?;

                            table_index += 1;
                        }
                    }
                    Ok(())
                },
            )?;

            let chip = BitSelectorChip::construct(config.config);
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
        let output = Fp::from(0);
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
        let output = Fp::from(1);
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

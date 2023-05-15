use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector, TableColumn},
    poly::Rotation,
};

use crate::utils::{decompose_word_be, enable_range, to_u32};

pub trait ByteSelectorInstructions<F: PrimeField> {
    fn select_byte(
        &self,
        layouter: &mut impl Layouter<F>,
        word: AssignedCell<F, F>,
        index: AssignedCell<F, F>,
        num_bytes: usize,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Debug, Clone)]
pub struct ByteSelectorChipConfig {
    byte_decomposition: Column<Advice>,
    lookup_index: Column<Advice>,
    byte_index: Column<Advice>,
    byte_selector: Column<Advice>,
    selector_acc: Column<Advice>,
    byte_acc: Column<Advice>,

    byte_decomposition_selector: Selector,
    is_bit_selector: Selector,
    selector_acc_selector: Selector,
    right_byte_selector: Selector,
    byte_acc_selector: Selector,
}

#[derive(Debug, Clone)]
pub struct ByteSelectorChip<F: PrimeField> {
    config: ByteSelectorChipConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> ByteSelectorChip<F> {
    pub fn construct(config: ByteSelectorChipConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        byte_decomposition: Column<Advice>,
        lookup_index: Column<Advice>,
        byte_index: Column<Advice>,
        byte_selector: Column<Advice>,
        selector_acc: Column<Advice>,
        byte_acc: Column<Advice>,
        byte_table: TableColumn,
    ) -> ByteSelectorChipConfig {
        let byte_decomposition_selector = meta.complex_selector();
        let is_bit_selector = meta.selector();
        let selector_acc_selector = meta.selector();
        let right_byte_selector = meta.selector();
        let byte_acc_selector = meta.selector();

        meta.lookup("byte_decomposition", |meta| {
            let byte_decomposition_selector = meta.query_selector(byte_decomposition_selector);
            let z_cur = meta.query_advice(byte_decomposition, Rotation::cur());

            // We recover the word from the difference of the running sums:
            //    z_i = 2^{K}⋅z_{i + 1} + a_i
            // => a_i = z_i - 2^{K}⋅z_{i + 1}
            let z_next = meta.query_advice(byte_decomposition, Rotation::next());
            let running_sum_word = z_cur.clone() - z_next * F::from(1 << 8);

            vec![(byte_decomposition_selector * running_sum_word, byte_table)]
        });

        meta.create_gate("selector_is_bit", |meta| {
            let is_bit_selector = meta.query_selector(is_bit_selector);
            let byte_selector = meta.query_advice(byte_selector, Rotation::cur());

            Constraints::with_selector(
                is_bit_selector,
                vec![byte_selector.clone() * byte_selector.clone() - byte_selector],
            )
        });

        meta.create_gate("selector_acc", |meta| {
            let selector_acc_selector = meta.query_selector(selector_acc_selector);
            let byte_selector_prev = meta.query_advice(byte_selector, Rotation::prev());
            let selector_acc_cur = meta.query_advice(selector_acc, Rotation::cur());
            let selector_acc_prev = meta.query_advice(selector_acc, Rotation::prev());

            Constraints::with_selector(
                selector_acc_selector,
                vec![selector_acc_cur - selector_acc_prev - byte_selector_prev],
            )
        });

        meta.create_gate("right_byte_selected", |meta| {
            let right_byte_selector = meta.query_selector(right_byte_selector);
            let lookup_index = meta.query_advice(lookup_index, Rotation::cur());
            let byte_index = meta.query_advice(byte_index, Rotation::cur());
            let byte_selector = meta.query_advice(byte_selector, Rotation::cur());

            Constraints::with_selector(
                right_byte_selector,
                vec![byte_selector * (lookup_index - byte_index)],
            )
        });

        meta.create_gate("byte_acc", |meta| {
            let byte_acc_selector = meta.query_selector(byte_acc_selector);
            let byte_acc_cur = meta.query_advice(byte_acc, Rotation::cur());
            let byte_acc_prev = meta.query_advice(byte_acc, Rotation::prev());

            // Reconstruct byte
            let z_prev = meta.query_advice(byte_decomposition, Rotation::prev());
            let z_cur = meta.query_advice(byte_decomposition, Rotation::cur());
            let byte = z_prev.clone() - z_cur * F::from(1 << 8);

            let byte_selector = meta.query_advice(byte_selector, Rotation::prev());

            Constraints::with_selector(
                byte_acc_selector,
                vec![byte_acc_cur - byte_acc_prev - byte_selector * byte],
            )
        });

        ByteSelectorChipConfig {
            byte_decomposition,
            lookup_index,
            byte_index,
            byte_selector,
            selector_acc,
            byte_acc,
            byte_decomposition_selector,
            is_bit_selector,
            selector_acc_selector,
            right_byte_selector,
            byte_acc_selector,
        }
    }
}

impl<F: PrimeField> ByteSelectorInstructions<F> for ByteSelectorChip<F> {
    fn select_byte(
        &self,
        layouter: &mut impl Layouter<F>,
        word: AssignedCell<F, F>,
        index: AssignedCell<F, F>,
        num_bytes: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "select_byte",
            |mut region| {
                // Bytes in **little endian** order
                let bytes = word.value().map(|word| {
                    decompose_word_be(word, num_bytes, 8)
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                });
                let ith_byte = bytes
                    .clone()
                    .zip(index.value())
                    .map(|(words, index)| words[num_bytes - 1 - to_u32(index) as usize]);
                let bytes = bytes.transpose_vec(num_bytes);

                let mut byte_decomposition = vec![word.value_field().evaluate()];
                let shift_factor = F::from(1 << 8).invert().unwrap();
                for byte in bytes {
                    let prev = byte_decomposition[byte_decomposition.len() - 1];
                    byte_decomposition.push(
                        byte.zip(prev)
                            .map(|(byte, prev)| (prev - byte) * shift_factor),
                    );
                }

                byte_decomposition[byte_decomposition.len() - 1]
                    .assert_if_known(|last_value| *last_value == F::ZERO);

                word.copy_advice(|| "word", &mut region, self.config.byte_decomposition, 0)?;
                for i in 1..(byte_decomposition.len() - 1) {
                    region.assign_advice(
                        || "byte_decompositon",
                        self.config.byte_decomposition,
                        i,
                        || byte_decomposition[i],
                    )?;
                }
                region.assign_advice_from_constant(
                    || "byte_decomposition_0",
                    self.config.byte_decomposition,
                    byte_decomposition.len() - 1,
                    F::ZERO,
                )?;

                for i in 0..(byte_decomposition.len() - 1) {
                    index.copy_advice(
                        || "lookup_index",
                        &mut region,
                        self.config.lookup_index,
                        i,
                    )?;
                }

                for i in 0..num_bytes {
                    region.assign_advice_from_constant(
                        || "byte_index",
                        self.config.byte_index,
                        // Bytes are listed in little endian order, but we want to select the
                        // ith byte assuming big endian order, so invert the index here.
                        num_bytes - 1 - i,
                        F::from(i as u64),
                    )?;
                }

                for i in 0..num_bytes {
                    let selector_value = index.value().map(|index| {
                        if (num_bytes - 1 - i) == to_u32(index) as usize {
                            F::ONE
                        } else {
                            F::ZERO
                        }
                    });
                    region.assign_advice(
                        || "selector",
                        self.config.byte_selector,
                        i,
                        || selector_value,
                    )?;
                }

                region.assign_advice_from_constant(
                    || "selector_acc_0",
                    self.config.selector_acc,
                    0,
                    F::ZERO,
                )?;
                for i in 1..num_bytes {
                    let selector_acc_value = index.value().map(|index| {
                        if (num_bytes - i) <= to_u32(index) as usize {
                            F::ONE
                        } else {
                            F::ZERO
                        }
                    });
                    region.assign_advice(
                        || "selector_acc",
                        self.config.selector_acc,
                        i,
                        || selector_acc_value,
                    )?;
                }
                region.assign_advice_from_constant(
                    || "selector_acc_1",
                    self.config.selector_acc,
                    byte_decomposition.len() - 1,
                    F::ONE,
                )?;

                let mut result = region.assign_advice_from_constant(
                    || "byte_acc_0",
                    self.config.byte_acc,
                    0,
                    F::ZERO,
                )?;
                for i in 1..byte_decomposition.len() {
                    let byte_acc_value = index.value().zip(ith_byte).map(|(index, ith_byte)| {
                        if (num_bytes - i) <= to_u32(index) as usize {
                            ith_byte
                        } else {
                            F::ZERO
                        }
                    });
                    result = region.assign_advice(
                        || "byte_acc",
                        self.config.byte_acc,
                        i,
                        || byte_acc_value,
                    )?;
                }

                enable_range(
                    &mut region,
                    self.config.byte_decomposition_selector,
                    0..byte_decomposition.len() - 1,
                )?;
                enable_range(
                    &mut region,
                    self.config.is_bit_selector,
                    0..byte_decomposition.len() - 1,
                )?;
                enable_range(
                    &mut region,
                    self.config.selector_acc_selector,
                    1..byte_decomposition.len(),
                )?;
                enable_range(
                    &mut region,
                    self.config.right_byte_selector,
                    0..byte_decomposition.len() - 1,
                )?;
                enable_range(
                    &mut region,
                    self.config.byte_acc_selector,
                    1..byte_decomposition.len(),
                )?;

                Ok(result)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ff::PrimeField;
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit, Column, Instance, TableColumn},
    };

    use super::{ByteSelectorChip, ByteSelectorChipConfig, ByteSelectorInstructions};

    #[derive(Default)]
    struct MyCircuit<F: PrimeField> {
        input: u64,
        index: u64,
        num_bytes: usize,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct Config {
        config: ByteSelectorChipConfig,
        instance: Column<Instance>,
        table_column: TableColumn,
    }

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let byte_decomposition = meta.advice_column();
            let lookup_index = meta.advice_column();
            let byte_index = meta.advice_column();
            let byte_selector = meta.advice_column();
            let selector_acc = meta.advice_column();
            let byte_acc = meta.advice_column();

            let instance = meta.instance_column();
            let constants = meta.fixed_column();
            let table_column = meta.lookup_table_column();

            meta.enable_equality(instance);
            meta.enable_equality(byte_decomposition);
            meta.enable_equality(lookup_index);
            meta.enable_equality(byte_index);
            meta.enable_equality(byte_selector);
            meta.enable_equality(selector_acc);
            meta.enable_equality(byte_acc);
            meta.enable_constant(constants);

            Config {
                config: ByteSelectorChip::configure(
                    meta,
                    byte_decomposition,
                    lookup_index,
                    byte_index,
                    byte_selector,
                    selector_acc,
                    byte_acc,
                    table_column,
                ),
                instance,
                table_column,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let (input_cell, index_cell) = layouter.assign_region(
                || "inputs",
                |mut region| {
                    let input_cell = region.assign_advice(
                        || "input",
                        config.config.byte_decomposition,
                        0,
                        || Value::known(F::from(self.input)),
                    )?;
                    let index_cell = region.assign_advice(
                        || "index",
                        config.config.lookup_index,
                        0,
                        || Value::known(F::from(self.index)),
                    )?;
                    Ok((input_cell, index_cell))
                },
            )?;

            layouter.assign_table(
                || "bytes",
                |mut table| {
                    for i in 0..(1 << 8) {
                        table.assign_cell(
                            || "byte",
                            config.table_column,
                            i,
                            || Value::known(F::from(i as u64)),
                        )?;
                    }
                    Ok(())
                },
            )?;

            let chip = ByteSelectorChip::construct(config.config);
            let result = chip.select_byte(&mut layouter, input_cell, index_cell, self.num_bytes)?;

            layouter.constrain_instance(result.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    #[test]
    fn test_1byte() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            input: 0xab,
            index: 0,
            num_bytes: 1,
            _marker: PhantomData,
        };
        let output = Fp::from(0xab);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_3byte_0() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            input: 0xabcdef,
            index: 0,
            num_bytes: 3,
            _marker: PhantomData,
        };
        let output = Fp::from(0xab);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_3byte_1() {
        let k = 9;
        let circuit = MyCircuit::<Fp> {
            input: 0xabcdef,
            index: 1,
            num_bytes: 3,
            _marker: PhantomData,
        };
        let output = Fp::from(0xcd);
        let prover = MockProver::run(k, &circuit, vec![vec![output]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn plot() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("byte-selector-layout.png", (512, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Byte Selector Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp> {
            input: 0xabcdef,
            index: 1,
            num_bytes: 3,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(4, &circuit, &root)
            .unwrap();
    }
}

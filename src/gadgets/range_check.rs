use ff::PrimeFieldBits;
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, TableColumn},
};

const K: usize = 8;

/// A thin wrapper around [`LookupRangeCheckConfig`] which uses `K = 8`, i.e., 8 bits per word
/// and allows for checking arbitrary amounts of bits.
#[derive(Clone, Debug)]
pub struct RangeCheckConfig<F: PrimeFieldBits> {
    range_check_config: LookupRangeCheckConfig<F, K>,
}

impl<F: PrimeFieldBits> RangeCheckConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        running_sum: Column<Advice>,
        byte_column: TableColumn,
    ) -> Self {
        let range_check_config = LookupRangeCheckConfig::configure(meta, running_sum, byte_column);
        Self { range_check_config }
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

use ff::PrimeFieldBits;
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Error, TableColumn},
};

const K: usize = 8;
pub type RangeCheckConfig<F> = LookupRangeCheckConfig<F, K>;

pub fn range_check<F: PrimeFieldBits>(
    mut layouter: impl Layouter<F>,
    range_check_config: RangeCheckConfig<F>,
    input: AssignedCell<F, F>,
    n_bits: usize,
) -> Result<(), Error> {
    #[allow(unstable_name_collisions)]
    let words = n_bits / K;
    let last_word = {
        if words > 0 {
            let running_sum = range_check_config.copy_check(
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
        range_check_config.copy_short_check(
            layouter.namespace(|| "range check (short)"),
            last_word,
            n_bits % K,
        )?;
    }
    Ok(())
}

pub fn load_range_check_lookup_table<F: PrimeFieldBits>(
    layouter: &mut impl Layouter<F>,
    table_column: TableColumn,
) -> Result<(), Error> {
    layouter.assign_table(
        || "table_idx",
        |mut table| {
            // We generate the row values lazily (we only need them during keygen).
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

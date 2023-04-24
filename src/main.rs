use hdf5::{File, Result};
use ndarray::{Ix1, Ix3, IxDyn};
use zero_g::wnn::Wnn;

fn main() -> Result<()> {
    let file = File::open("models/model_28input_1024entry_2hash_2bpi.pickle.hdf5")?;
    for attr_name in file.attr_names()? {
        let attr = file.attr(&attr_name)?.read_scalar::<i64>()?;
        println!("{attr_name}: {attr}");
    }

    let num_classes = file.attr("num_classes")?.read_scalar::<i64>()? as usize;
    let num_inputs = file.attr("num_inputs")?.read_scalar::<i64>()? as usize;
    let bits_per_input = file.attr("bits_per_input")?.read_scalar::<i64>()? as usize;
    let num_filter_inputs = file.attr("num_filter_inputs")?.read_scalar::<i64>()? as usize;
    let num_filter_entries = file.attr("num_filter_entries")?.read_scalar::<i64>()? as usize;
    let num_filter_hashes = file.attr("num_filter_hashes")?.read_scalar::<i64>()? as usize;
    let p = file.attr("p")?.read_scalar::<i64>()? as u64;

    let expected_shape = [
        num_classes,
        num_inputs * bits_per_input / num_filter_inputs,
        num_filter_entries,
    ];

    let bloom_filters = file.dataset("bloom_filters")?;
    let bloom_filters = bloom_filters.read::<bool, Ix3>()?;
    assert_eq!(bloom_filters.shape(), expected_shape);

    let input_order = file.dataset("input_order")?;
    let input_order = input_order.read::<u64, Ix1>()?;
    let num_input_bits = num_inputs * bits_per_input;
    assert_eq!(input_order.shape(), [num_input_bits]);

    let wnn = Wnn::new(
        bits_per_input,
        num_classes,
        num_filter_entries,
        num_filter_hashes,
        num_filter_inputs,
        num_inputs,
        p,
        bloom_filters,
        input_order,
    );
    let input_bits = Vec::from((0..num_input_bits).map(|_| false).collect::<Vec<_>>());
    wnn.predict(input_bits);

    Ok(())
}

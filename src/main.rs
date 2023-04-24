use hdf5::{File, Result};
use ndarray::IxDyn;

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

    let expected_shape = [
        num_classes,
        num_inputs * bits_per_input / num_filter_inputs,
        num_filter_entries,
    ];

    let bloom_filters = file.dataset("bloom_filters")?;
    let bloom_filters = bloom_filters.read::<bool, IxDyn>()?;

    let shape = bloom_filters.shape();
    println!("{:?}", shape);
    assert_eq!(shape, expected_shape);
    Ok(())
}

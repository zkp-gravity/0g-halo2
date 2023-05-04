use hdf5::{File, Result};
use ndarray::{Ix1, Ix3};

use crate::wnn::Wnn;

pub fn load_wnn<const P: u64, const L: usize, const N_HASHES: usize, const BITS_PER_HASH: usize>(
    path: &str,
) -> Result<Wnn<P, L, N_HASHES, BITS_PER_HASH>> {
    let file = File::open(path)?;
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

    assert_eq!(p, P);
    assert_eq!(num_filter_entries.pow(num_filter_hashes as u32), 1 << L);
    assert_eq!(num_filter_hashes, N_HASHES);
    assert_eq!(num_filter_entries, 1 << BITS_PER_HASH);

    let expected_shape = [
        num_classes,
        num_inputs * bits_per_input / num_filter_inputs,
        num_filter_entries,
    ];
    let bloom_filters = file.dataset("bloom_filters")?;
    let bloom_filters = bloom_filters.read::<bool, Ix3>()?;
    assert_eq!(bloom_filters.shape(), expected_shape);

    let width = (num_inputs as f32).sqrt() as usize;
    let expected_shape = [width, width, bits_per_input];
    let binarization_thresholds = file.dataset("binarization_thresholds")?;
    let binarization_thresholds = binarization_thresholds.read::<f32, Ix3>()?;
    let binarization_thresholds = binarization_thresholds * 255.0;
    assert_eq!(binarization_thresholds.shape(), expected_shape);

    let input_order = file.dataset("input_order")?;
    let input_order = input_order.read::<u64, Ix1>()?;
    let num_input_bits = num_inputs * bits_per_input;
    assert_eq!(input_order.shape(), [num_input_bits]);

    Ok(Wnn::<P, L, N_HASHES, BITS_PER_HASH>::new(
        num_classes,
        num_filter_entries,
        num_filter_hashes,
        num_filter_inputs,
        p,
        bloom_filters,
        input_order,
        binarization_thresholds,
    ))
}

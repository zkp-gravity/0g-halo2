//! Utilities for loading images and WNNs from disk.

use std::path::Path;

use hdf5::{File, Result};
use image::ImageError;
use ndarray::{s, Array, Array2, Array3};
use ndarray::{Ix1, Ix3};

use crate::wnn::Wnn;

/// Loads a grayscale image from disk, returning the first channel.
pub fn load_grayscale_image(img_path: &Path) -> Result<Array2<u8>, ImageError> {
    let image = image::open(img_path)?.to_rgb8();
    let array: Array3<u8> = Array::from_shape_vec(
        (image.height() as usize, image.width() as usize, 3),
        image.into_raw(),
    )
    .expect("Error converting image to ndarray");

    Ok(array.slice_move(s![.., .., 0]))
}

/// Loads a [`Wnn`] from disk, from a file following [this format](https://github.com/zkp-gravity/BTHOWeN-0g/blob/master/output_format_spec.md).
pub fn load_wnn(path: &Path) -> Result<Wnn> {
    let file = File::open(path)?;

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

    let width = (num_inputs as f32).sqrt() as usize;
    let expected_shape = [width, width, bits_per_input];
    let binarization_thresholds = file.dataset("binarization_thresholds")?;
    let binarization_thresholds = binarization_thresholds.read::<f32, Ix3>()?;
    let binarization_thresholds = binarization_thresholds * 255.0;
    assert_eq!(binarization_thresholds.shape(), expected_shape);

    // Quantize binarization thresholds.
    // This should make no difference to the accuracy of the model,
    // because images are quantized to u8 anyway.
    // Note that:
    // - We use ceil(), because <u8> >= <f32> <==> <u8> >= <f32>.ceil() as u8
    // - We clamp at 0, because intensities cannot be negative
    // - We clamp at **256**, because intensities cannot be greater than 255
    //   Note that thresholds set to 256 will never be reached!
    //   Also note that for this reason, we can't use u8 to store the thresholds.
    let binarization_thresholds = binarization_thresholds * 255.0;
    let binarization_thresholds =
        binarization_thresholds.map(|x| x.ceil().max(0.0).min(256.0) as u16);

    let input_order = file.dataset("input_order")?;
    let input_order = input_order.read::<u64, Ix1>()?;
    let num_input_bits = num_inputs * bits_per_input;
    assert_eq!(input_order.shape(), [num_input_bits]);

    Ok(Wnn::new(
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

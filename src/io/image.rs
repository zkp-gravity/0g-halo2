use std::path::PathBuf;

use image::ImageError;
use ndarray::{s, Array, Array2, Array3};

pub fn load_image(img_path: PathBuf) -> Result<Array2<u8>, ImageError> {
    let image = image::open(img_path)?.to_rgb8();
    let array: Array3<u8> = Array::from_shape_vec(
        (image.height() as usize, image.width() as usize, 3),
        image.into_raw(),
    )
    .expect("Error converting image to ndarray");

    let array = array.slice_move(s![.., .., 0]);

    Ok(array)
}

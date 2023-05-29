use std::path::Path;

use zero_g::{load_grayscale_image, load_wnn};

const IMG_PATH: &str = "benches/example_image_7.png";
const MODEL_PATH_MNIST_TINY: &str = "models/model_28input_256entry_1hash_1bpi.hdf5";
const MODEL_PATH_MNIST_SMALL: &str = "models/model_28input_1024entry_2hash_2bpi.hdf5";

/// Analogously to the benchmark, mock-proofs the checked-in image using the "MNIST Tiny" model.
#[test]
fn mock_proof_mnist_tiny() {
    let img = load_grayscale_image(Path::new(IMG_PATH)).unwrap();
    let wnn = load_wnn(Path::new(MODEL_PATH_MNIST_TINY)).unwrap();
    wnn.mock_proof(&img, 12);
}

#[test]
fn snapshot_mnist_tiny_predictions() {
    let img = load_grayscale_image(Path::new(IMG_PATH)).unwrap();
    let wnn = load_wnn(Path::new(MODEL_PATH_MNIST_TINY)).unwrap();
    let predictions = wnn.predict(&img);
    assert_eq!(predictions, vec![9, 6, 13, 10, 17, 10, 9, 26, 11, 16]);
}

/// Mock-proofs the checked-in image using the "MNIST Small" model.
#[test]
fn mock_proof_mnist_small() {
    let img = load_grayscale_image(Path::new(IMG_PATH)).unwrap();
    let wnn = load_wnn(Path::new(MODEL_PATH_MNIST_SMALL)).unwrap();
    wnn.mock_proof(&img, 17);
}

#[test]
fn snapshot_mnist_small_predictions() {
    let img = load_grayscale_image(Path::new(IMG_PATH)).unwrap();
    let wnn = load_wnn(Path::new(MODEL_PATH_MNIST_SMALL)).unwrap();
    let predictions = wnn.predict(&img);
    assert_eq!(predictions, vec![17, 13, 25, 27, 29, 21, 15, 55, 27, 32]);
}

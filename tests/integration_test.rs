use std::path::Path;

use zero_g::{checked_in_test_data::*, load_grayscale_image, load_wnn};

#[test]
fn mock_proof_mnist_tiny() {
    let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
    let (k, model_path) = MNIST_TINY;
    let wnn = load_wnn(Path::new(model_path)).unwrap();
    wnn.mock_proof(&img, k);
}

#[test]
fn snapshot_mnist_tiny_predictions() {
    let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
    let (_, model_path) = MNIST_TINY;
    let wnn = load_wnn(Path::new(model_path)).unwrap();
    let predictions = wnn.predict(&img);
    assert_eq!(predictions, vec![9, 6, 13, 10, 17, 10, 9, 26, 11, 16]);
}

#[test]
fn mock_proof_mnist_small() {
    let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
    let (k, model_path) = MNIST_SMALL;
    let wnn = load_wnn(Path::new(model_path)).unwrap();
    wnn.mock_proof(&img, k);
}

#[test]
fn snapshot_mnist_small_predictions() {
    let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
    let (_, model_path) = MNIST_SMALL;
    let wnn = load_wnn(Path::new(model_path)).unwrap();
    let predictions = wnn.predict(&img);
    assert_eq!(predictions, vec![17, 13, 25, 27, 29, 21, 15, 55, 27, 32]);
}

#[test]
fn mock_proof_mnist_medium() {
    let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
    let (k, model_path) = MNIST_MEDIUM;
    let wnn = load_wnn(Path::new(model_path)).unwrap();
    wnn.mock_proof(&img, k);
}

#[test]
fn snapshot_mnist_medium_predictions() {
    let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
    let (_, model_path) = MNIST_MEDIUM;
    let wnn = load_wnn(Path::new(model_path)).unwrap();
    let predictions = wnn.predict(&img);
    assert_eq!(predictions, vec![29, 21, 40, 47, 45, 41, 28, 82, 35, 66]);
}

#[test]
fn mock_proof_mnist_large() {
    let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
    let (k, model_path) = MNIST_LARGE;
    let wnn = load_wnn(Path::new(model_path)).unwrap();
    wnn.mock_proof(&img, k);
}

#[test]
fn snapshot_mnist_large_predictions() {
    let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
    let (_, model_path) = MNIST_LARGE;
    let wnn = load_wnn(Path::new(model_path)).unwrap();
    let predictions = wnn.predict(&img);
    assert_eq!(predictions, vec![16, 10, 22, 22, 29, 25, 9, 91, 21, 51]);
}

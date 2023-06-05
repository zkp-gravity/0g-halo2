//! Imlements zk-SNARKs for [BTHOWeN](https://arxiv.org/abs/2203.01479)-style weightless neural networks (WNNs).
//!
//! # Example
//! ```
//! use std::path::Path;
//! use zero_g::{checked_in_test_data::*, load_grayscale_image, load_wnn};
//! use halo2_proofs::poly::{
//!     commitment::ParamsProver, kzg::commitment::ParamsKZG,
//! };
//!
//! let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
//! let (k, model_path) = MNIST_TINY;
//! let wnn = load_wnn(Path::new(model_path)).unwrap();
//!
//! // Asserts that all constraints are satisfied
//! wnn.mock_proof(&img, k);
//!
//! // Generate keys
//! let kzg_params = ParamsKZG::new(k);
//! let pk = wnn.generate_proving_key(&kzg_params);
//!
//! // Generate proof
//! let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);
//!
//! // Verify proof
//! wnn.verify_proof(&proof, &kzg_params, pk.get_vk(), &outputs);
//! ```

pub mod gadgets;
pub mod io;
pub mod utils;
pub mod wnn;

pub use io::{load_grayscale_image, load_wnn};
pub use wnn::Wnn;

pub mod checked_in_test_data {
    pub const TEST_IMG_PATH: &str = "benches/example_image_7.png";

    // For each model, we store the path and the minimal value for `k` needed (assuming SimpleFloorPlanner)
    pub const MNIST_TINY: (u32, &str) = (14, "models/model_28input_256entry_1hash_1bpi.hdf5");
    pub const MNIST_SMALL: (u32, &str) = (15, "models/model_28input_1024entry_2hash_2bpi.hdf5");
    pub const MNIST_MEDIUM: (u32, &str) = (15, "models/model_28input_2048entry_2hash_3bpi.hdf5");
    pub const MNIST_LARGE: (u32, &str) = (17, "models/model_49input_8192entry_4hash_6bpi.hdf5");
}

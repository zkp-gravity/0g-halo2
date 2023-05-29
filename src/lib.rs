//! Imlements zk-SNARKs for [BTHOWeN](https://arxiv.org/abs/2203.01479)-style weightless neural networks (WNNs).
//!
//! # Example
//! ```
//! use zero_g::{load_image, load_wnn};
//! use halo2_proofs::poly::{
//!     commitment::ParamsProver, kzg::commitment::ParamsKZG,
//! };
//!
//! let img = load_image(&Path::new("benches/example_image_7.png")).unwrap();
//! let wnn = load_wnn(&Path::new("models/model_28input_256entry_1hash_1bpi.pickle.hdf5")).unwrap();
//!
//! // Asserts that all constraints are satisfied
//! wnn.mock_proof(&img, 12);
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

pub use io::{load_image, load_wnn};
pub use wnn::Wnn;

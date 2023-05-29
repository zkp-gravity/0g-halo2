# `zero_g` - Proof of inference of Weightless Neural Networks using Halo2

In this project, we're developing a Halo2 implementation of the [Zero Gravity](https://hackmd.io/nCoxJCMlTqOr41_r1W4S9g?view) project as part of a [grant](https://hackmd.io/@guard/BJ4UPK-fn) from the Ethereum Foundation.

## Setup

To get started:
- Install version 1.12.2 of [HDF5](https://github.com/mokus0/hdf5/blob/master/release_docs/INSTALL)
- Install [Rust](https://www.rust-lang.org/tools/install)
- Run the tests: `cargo test`
- Run the benchmarks: `cargo bench`
- Build the binaries: `cargo build --release`

Two models trained on MNIST are checked-in and located in [`models`](models).
To add your own models, follow the steps from the [`BTHOWeN-zero-g` readme](https://github.com/zkp-gravity/BTHOWeN-zero-g/blob/master/README.md) to train a model, convert it to HDF5 and optionally export the MNIST dataset to `data/MNIST/png/`.

## Command-line tool

You can install the command line tool by running `cargo install --path .`.
Then, run `zero_g --help` for documentation of the tool.

Here are a few examples:
- `zero_g predict models/model_28input_256entry_1hash_1bpi.hdf5 benches/example_image_7.png` classifies a single image.
- `zero_g compute-accuracy models/model_28input_256entry_1hash_1bpi.hdf5` computes the accuracy on the MNIST test set. This should yield the same number as the `evaluate.py` script in the `BTHOWeN-zero-g` repository.
- `zero_g proof models/model_28input_256entry_1hash_1bpi.hdf5 benches/example_image_7.png 12` classifies a single image, generates the keys & proof, and verifies the proof.

## Using `zero_g` as a library

If you want to verify WNN predictions in your own circuit, you can do so by using the `WnnChip` implemented in the `zero_g` crate.
Run `cargo doc --open` to open up the documentation, and see [`tests/using_zero_g_as_a_library.rs`](tests/using_zero_g_as_a_library.rs) for an example.
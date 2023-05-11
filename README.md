# zero_g

In this project, we're developing a Halo2 implementation of the [Zero Gravity](https://hackmd.io/nCoxJCMlTqOr41_r1W4S9g?view) project as part of a [grant](https://hackmd.io/@guard/BJ4UPK-fn) from the Ethereum Foundation.

## Usage

There are serveral steps involved to generate proofs:
- [Rust](https://www.rust-lang.org/tools/install) needs to be installed.
- Follow the steps from the [`BTHOWeN-zero-g` readme](https://github.com/zkp-gravity/BTHOWeN-zero-g/blob/master/README.md) to train a model, convert it to HDF5 and optionally export the MNIST dataset. Part of the code currently assumes that models are stored in a `models` directory and the MNIST dataset is stored in `data/MNIST/png/`. For example, you can symlink `data -> ../BTHOWeN/software_model/data` and `models -> ../BTHOWeN/software_model/models/MNIST`.
- `cargo run --release -- predict models/model_28input_256entry_1hash_1bpi.pickle.hdf5 data/MNIST/png/0000_7.png` classifies a single image.
- `cargo run --release -- compute-accuracy models/model_28input_256entry_1hash_1bpi.pickle.hdf5` computes the accuracy on the MNIST test set. This should yield the same number as the `evaluate.py` script in the `BTHOWeN-zero-g` repository.
- `cargo run --release -- proof models/model_28input_256entry_1hash_1bpi.pickle.hdf5 data/MNIST/png/0000_7.png 17` classifies a single image, generates the keys & proof, and verifies the proof.

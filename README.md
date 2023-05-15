# zero_g

In this project, we're developing a Halo2 implementation of the [Zero Gravity](https://hackmd.io/nCoxJCMlTqOr41_r1W4S9g?view) project as part of a [grant](https://hackmd.io/@guard/BJ4UPK-fn) from the Ethereum Foundation.

## Usage

There are serveral steps involved to generate proofs:
- [Rust](https://www.rust-lang.org/tools/install) needs to be installed.
- [HDF5](https://github.com/mokus0/hdf5/blob/master/release_docs/INSTALL) version 1.12.2 needs to be installed.
- Follow the steps from the [`BTHOWeN-zero-g` readme](https://github.com/zkp-gravity/BTHOWeN-zero-g/blob/master/README.md) to train a model, convert it to HDF5 and export the MNIST dataset. Code currently assumes that we use model `MNIST --filter_inputs 28 --filter_entries 256 --filter_hashes 1 --bits_per_input 1` which hdf5 representation is stored in a `models` directory and the MNIST dataset is stored in `data/MNIST/png/`. For example, you can symlink `data -> ../BTHOWeN/software_model/data` and `models -> ../BTHOWeN/software_model/models/MNIST`.
- `cargo run --release -- predict data/MNIST/png/0000_7.png` classifies a single image.
- `cargo run --release -- compute-accuracy` computes the accuracy on the MNIST test set. This should yield the same number as the `evaluate.py` script in the `BTHOWeN-zero-g` repository.
- `cargo run --release -- proof data/MNIST/png/0000_7.png 17` classifies a single image, generates the keys & proof, and verifies the proof.

#!/bin/bash
set -e

cargo run --release -- help

ZERO_G="target/release/zero_g"

echo ""
echo "==== Running predict"
$ZERO_G predict \
    -m models/model_28input_256entry_1hash_1bpi.hdf5 \
    -i benches/example_image_7.png

if [ -d "data/MNIST/png" ]; then
    echo ""
    echo "==== Running compute-accuracy"
    $ZERO_G compute-accuracy \
        -m models/model_28input_256entry_1hash_1bpi.hdf5 \
        -t data/MNIST/png/
fi

echo ""
echo "==== Running mock-proof"
$ZERO_G mock-proof \
    -m models/model_28input_256entry_1hash_1bpi.hdf5 \
    -i benches/example_image_7.png \
    -k 14

echo ""
echo "==== Running generate-srs"
$ZERO_G generate-srs \
    -k 14

echo ""
echo "==== Running generate-keys"
$ZERO_G generate-keys \
    -m models/model_28input_256entry_1hash_1bpi.hdf5 \
    -k 14

echo ""
echo "==== Running dry-run-evm-verifier"
$ZERO_G dry-run-evm-verifier \
    -m models/model_28input_256entry_1hash_1bpi.hdf5 \
    -i benches/example_image_7.png \
    -k 14

echo ""
echo "==== Running deploy-evm-verifier"
$ZERO_G deploy-evm-verifier \
    -m models/model_28input_256entry_1hash_1bpi.hdf5 \
    -k 14

echo ""
echo "==== Running proof"
$ZERO_G proof \
    -m models/model_28input_256entry_1hash_1bpi.hdf5 \
    -i benches/example_image_7.png \
    -k 14

echo ""
echo "==== Running verify"
$ZERO_G verify \
    -m models/model_28input_256entry_1hash_1bpi.hdf5 \
    -i benches/example_image_7.png \
    -k 14

echo ""
echo "==== Running submit-proof"
$ZERO_G submit-proof \
    -m models/model_28input_256entry_1hash_1bpi.hdf5 \
    -i benches/example_image_7.png \
    -k 14
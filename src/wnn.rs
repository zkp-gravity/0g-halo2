//! Module implementing the a weightless neural network (WNN), with the ability to proof inference.

use std::time::Instant;

use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use ndarray::{s, Array1, Array2, Array3};

use halo2_proofs::halo2curves::bn256::{Bn256, Fr as Fp, G1Affine};
use num_bigint::BigUint;
use rand_core::OsRng;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;

use crate::gadgets::wnn::{WnnCircuit, WnnCircuitParams};

/// Implementation of a [BTHOWeN](https://arxiv.org/abs/2203.01479)-style weightless neural network (WNN).
pub struct Wnn {
    /// Number of classes (e.g. 10 for MNIST)
    num_classes: usize,

    /// Number fo input bits per filter
    num_filter_inputs: usize,

    /// The length of the bloom filter array
    num_filter_entries: usize,

    /// The number of hashes used by the bloom filter
    num_filter_hashes: usize,

    /// Prime `p` used in the MishMash hash function
    p: u64,

    /// Bloom filter array, shape (num_classes, num_inputs * bits_per_input / num_filter_inputs, num_filter_entries)
    bloom_filters: Array3<bool>,
    /// Permutation of input bits, shape (num_inputs * bits_per_input)
    input_permutation: Array1<u64>,
    /// Thresholds for pixels, shape (width, height, bits_per_input)
    /// The numbers are in the range [0, 256].
    binarization_thresholds: Array3<u16>,
}

impl Wnn {
    /// Constructs a new WNN.
    /// Instead of calling this function directly, consider using [`crate::load_wnn`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        num_classes: usize,
        num_filter_entries: usize,
        num_filter_hashes: usize,
        num_filter_inputs: usize,
        p: u64,

        bloom_filters: Array3<bool>,
        input_order: Array1<u64>,
        binarization_thresholds: Array3<u16>,
    ) -> Self {
        Self {
            num_classes,
            num_filter_entries,
            num_filter_hashes,
            num_filter_inputs,
            p,
            bloom_filters,
            input_permutation: input_order,
            binarization_thresholds,
        }
    }

    /// Implements the thermometer encoding: Each pixels is mapped to a vector
    /// of bits, one per threshold. The bit is set if the pixel value is greater
    /// than or equal to the threshold.
    fn thermometer_encoding(&self, image: &Array2<u8>) -> Vec<bool> {
        let (width, height) = (image.shape()[0], image.shape()[1]);

        let mut image_bits = vec![];

        for b in 0..self.binarization_thresholds.shape()[2] {
            for i in 0..width {
                for j in 0..height {
                    image_bits
                        .push(image[(i, j)] as u16 >= self.binarization_thresholds[(i, j, b)]);
                }
            }
        }

        image_bits
    }

    /// Computes the MishMash hash: `x^3 % p % 2^l`
    fn mish_mash_hash(&self, x: u64) -> BigUint {
        let x = BigUint::from(x);
        let modulus = BigUint::from(self.num_filter_entries).pow(self.num_filter_hashes as u32);
        ((&x * &x * &x) % self.p) % modulus
    }

    /// Encodes an image into a vector of filter indices
    fn encode_image(&self, image: &Array2<u8>) -> Vec<u64> {
        let image_bits = self.thermometer_encoding(image);
        assert_eq!(image_bits.len(), self.input_permutation.shape()[0]);

        // Permute inputs
        let permuted_bits = self
            .input_permutation
            .iter()
            .map(|i| image_bits[*i as usize])
            .collect::<Vec<_>>();

        // Pack inputs into integers of `num_filter_inputs` bits
        // (LITTLE endian order)
        permuted_bits
            .chunks_exact(self.num_filter_inputs)
            .map(|chunk| {
                chunk
                    .iter()
                    .rev()
                    .fold(0, |acc, b| (acc << 1) + (*b as u64))
            })
            .collect()
    }

    /// Computes the bloom filter response for the given index.
    ///
    /// The index is hashed, split into multiple array indices.
    /// The bloom filter response is true if all of the corresponding
    /// array entries are true.
    fn bloom_filter_lookup(&self, bloom_array: &[bool], filter_index: u64) -> bool {
        let hash = self.mish_mash_hash(filter_index);

        // Split hash into multiple indices
        let array_indices: Vec<usize> = (0..self.num_filter_hashes)
            .map(|i| {
                ((&hash / BigUint::from(self.num_filter_entries).pow(i as u32))
                    % self.num_filter_entries)
                    .try_into()
                    .unwrap()
            })
            .collect();

        array_indices.into_iter().all(|i| bloom_array[i])
    }

    /// Predicts a given image
    pub fn predict(&self, image: &Array2<u8>) -> Vec<u64> {
        let filter_indices = self.encode_image(image);
        assert_eq!(filter_indices.len(), self.bloom_filters.shape()[1]);

        // Look up bloom filters
        (0..self.num_classes)
            .map(|c| {
                filter_indices
                    .iter()
                    .enumerate()
                    .map(|(index_of_filter, index_into_filter)| {
                        let bloom_filter_array = self
                            .bloom_filters
                            .slice(s![c, index_of_filter, ..])
                            .to_slice()
                            .unwrap();
                        self.bloom_filter_lookup(bloom_filter_array, *index_into_filter) as u64
                    })
                    .sum()
            })
            .collect()
    }

    /// Returns the Halo2 circuit corresponding to this WNN.
    pub fn get_circuit(&self, image: &Array2<u8>) -> WnnCircuit<Fp> {
        let params = WnnCircuitParams {
            p: self.p,
            l: self.num_filter_hashes * (self.num_filter_entries as f32).log2() as usize,
            n_hashes: self.num_filter_hashes,
            bits_per_hash: (self.num_filter_entries as f32).log2() as usize,
            bits_per_filter: self.num_filter_inputs,
        };
        WnnCircuit::new(
            image.clone(),
            self.bloom_filters.clone(),
            self.binarization_thresholds.clone(),
            self.input_permutation.clone(),
            params,
        )
    }

    /// Plots the circuit corresponding to this WNN.
    pub fn plot_circuit(&self, filename: &str, k: u32) {
        let image = Array2::zeros(self.img_shape());
        self.get_circuit(&image).plot(filename, k);
    }

    /// Check that the circuit is satisfied for the given image.
    pub fn mock_proof(&self, image: &Array2<u8>, k: u32) {
        let outputs: Vec<Fp> = self.predict(image).into_iter().map(Fp::from).collect();
        let circuit = self.get_circuit(image);

        let prover = MockProver::run(k, &circuit, vec![outputs]).unwrap();
        prover.assert_satisfied();
    }

    fn img_shape(&self) -> (usize, usize) {
        (
            self.binarization_thresholds.shape()[0],
            self.binarization_thresholds.shape()[1],
        )
    }

    /// Generate a proving key and verification key.
    ///
    /// The verification key can be accessed via `pk.get_vk()`.
    pub fn generate_proving_key(&self, kzg_params: &ParamsKZG<Bn256>) -> ProvingKey<G1Affine> {
        // They keys should not depend on the input, so we're generating a dummy input here
        let circuit = self.get_circuit(&Array2::zeros(self.img_shape()));

        let vk = keygen_vk(kzg_params, &circuit).expect("keygen_vk should not fail");

        keygen_pk(kzg_params, vk, &circuit).expect("keygen_pk should not fail")
    }

    /// Generate a proof for the given image.
    pub fn proof(
        &self,
        pk: &ProvingKey<G1Affine>,
        kzg_params: &ParamsKZG<Bn256>,
        image: &Array2<u8>,
    ) -> (Vec<u8>, Vec<Fp>) {
        let outputs: Vec<Fp> = self.predict(image).into_iter().map(Fp::from).collect();

        let circuit = self.get_circuit(image);
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<_>,
            _,
            _,
            // Use `EvmTranscript` (based on keccak256) so that proofs are verifiable
            // with the EVM verifier
            EvmTranscript<_, _, _, _>,
            _,
        >(
            kzg_params,
            pk,
            &[circuit],
            &[&[outputs.as_ref()]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();
        (proof, outputs)
    }

    /// Verify the given proof.
    pub fn verify_proof(
        &self,
        proof: &[u8],
        kzg_params: &ParamsKZG<Bn256>,
        vk: &VerifyingKey<G1Affine>,
        outputs: &Vec<Fp>,
    ) {
        let transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
        let strategy = SingleStrategy::new(kzg_params);
        verify_proof::<_, VerifierGWC<Bn256>, _, _, _>(
            kzg_params,
            vk,
            strategy.clone(),
            &[&[outputs.as_ref()]],
            &mut transcript.clone(),
        )
        .unwrap();
    }

    /// Generate a proof and verify it.
    pub fn proof_and_verify(&self, image: &Array2<u8>, k: u32) {
        println!("Key gen...");
        let start = Instant::now();

        let kzg_params = ParamsKZG::new(k);
        let pk = self.generate_proving_key(&kzg_params);

        let duration = start.elapsed();
        println!("Took: {:?}", duration);

        println!("Proving...");
        let start = Instant::now();

        let (proof, outputs) = self.proof(&pk, &kzg_params, image);

        let duration = start.elapsed();
        println!("Took: {:?}", duration);

        println!("Verifying...");
        let start = Instant::now();

        self.verify_proof(&proof, &kzg_params, pk.get_vk(), &outputs);

        let duration = start.elapsed();
        println!("Took: {:?}", duration);

        println!("Done!");
    }
}

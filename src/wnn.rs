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
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use ndarray::{Array1, Array2, Array3};

use halo2_proofs::halo2curves::bn256::{Bn256, Fr as Fp, G1Affine};
use num_bigint::BigUint;
use rand_core::OsRng;

use crate::gadgets::wnn::{WnnCircuit, WnnCircuitParams};

pub struct Wnn {
    num_classes: usize,
    num_filter_entries: usize,
    num_filter_hashes: usize,
    num_filter_inputs: usize,
    p: u64,

    /// Bloom filter array, shape (num_classes, num_inputs * bits_per_input / num_filter_inputs, num_filter_entries)
    bloom_filters: Array3<bool>,
    /// Permutation of input bits, shape (num_inputs * bits_per_input)
    input_permutation: Array1<u64>,
    /// Thresholds for pixels, shape (width, height, bits_per_input)
    binarization_thresholds: Array3<f32>,
}

/// Implementation of a [BTHOWeN](https://arxiv.org/abs/2203.01479)-style weightless neural network (WNN).
///
/// Implements model inference and proof of inference.
///
/// # Example
/// ```
/// use zero_g::io::{image::load_image, model::load_wnn};
/// use halo2_proofs::poly::{
///     commitment::ParamsProver, kzg::commitment::ParamsKZG,
/// };
/// use std::path::Path;
///
/// let img = load_image(&Path::new("benches/example_image_7.png")).unwrap();
/// let wnn = load_wnn(&Path::new("models/model_28input_256entry_1hash_1bpi.pickle.hdf5")).unwrap();
/// let k = 12;
///
/// // Asserts that all constraints are satisfied
/// wnn.mock_proof(&img, k);
///
/// // Generate keys
/// let kzg_params = ParamsKZG::new(k);
/// let pk = wnn.generate_proving_key(&kzg_params);
///
/// // Generate proof
/// let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);
///
/// // Verify proof
/// wnn.verify_proof(&proof, &kzg_params, pk.get_vk(), &outputs);
/// ```
impl Wnn {
    pub fn new(
        num_classes: usize,
        num_filter_entries: usize,
        num_filter_hashes: usize,
        num_filter_inputs: usize,
        p: u64,

        bloom_filters: Array3<bool>,
        input_order: Array1<u64>,
        binarization_thresholds: Array3<f32>,
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

    pub fn num_input_bits(&self) -> usize {
        self.input_permutation.len()
    }

    pub fn encode_image(&self, image: &Array2<u8>) -> Vec<bool> {
        let (width, height) = (image.shape()[0], image.shape()[1]);

        let mut image_bits = vec![];

        for b in 0..self.binarization_thresholds.shape()[2] {
            for i in 0..width {
                for j in 0..height {
                    image_bits
                        .push(image[(i, j)] as f32 >= self.binarization_thresholds[(i, j, b)]);
                }
            }
        }

        image_bits
    }

    fn mish_mash_hash(&self, x: u64) -> BigUint {
        let x = BigUint::from(x);
        let modulus = BigUint::from(self.num_filter_entries).pow(self.num_filter_hashes as u32);
        ((&x * &x * &x) % self.p) % modulus
    }

    fn compute_hash_inputs(&self, input_bits: Vec<bool>) -> Vec<u64> {
        assert_eq!(input_bits.len(), self.input_permutation.shape()[0]);

        // Permute inputs
        let inputs_permuted: Vec<bool> = self
            .input_permutation
            .iter()
            .map(|i| input_bits[*i as usize])
            .collect();

        // Pack inputs into integers of `num_filter_inputs` bits
        // (LITTLE endian order)
        inputs_permuted
            .chunks_exact(self.num_filter_inputs)
            .map(|chunk| {
                chunk
                    .iter()
                    .rev()
                    .fold(0, |acc, b| (acc << 1) + (*b as u64))
            })
            .collect()
    }

    pub fn predict(&self, image: &Array2<u8>) -> Vec<u32> {
        let input_bits = self.encode_image(image);
        let hash_inputs = self.compute_hash_inputs(input_bits);
        // This asserts that the number of filter inputs does not exceed the number of bits in a u64
        assert_eq!(hash_inputs.len(), self.bloom_filters.shape()[1]);

        // Hash
        let hash_outputs: Vec<BigUint> = hash_inputs
            .into_iter()
            .map(|x| self.mish_mash_hash(x))
            .collect();
        assert_eq!(hash_outputs.len(), self.bloom_filters.shape()[1]);

        // Split hashes
        let bloom_indices: Vec<Vec<usize>> = hash_outputs
            .into_iter()
            .map(|h| {
                (0..self.num_filter_hashes)
                    .map(|i| {
                        ((&h / BigUint::from(self.num_filter_entries).pow(i as u32))
                            % self.num_filter_entries)
                            .try_into()
                            .unwrap()
                    })
                    .collect()
            })
            .collect();
        assert_eq!(bloom_indices.len(), self.bloom_filters.shape()[1]);

        // Look up bloom filters
        (0..self.num_classes)
            .map(|c| {
                bloom_indices
                    .iter()
                    .enumerate()
                    .map(|(input_index, indices)| {
                        indices
                            .iter()
                            .map(|i| self.bloom_filters[(c, input_index, *i)])
                            .fold(true, |acc, b| acc && b) as u32
                    })
                    .sum::<u32>()
            })
            .collect::<Vec<_>>()
    }

    fn get_circuit(&self, hash_inputs: Vec<u64>) -> WnnCircuit<Fp> {
        let params = WnnCircuitParams {
            p: self.p,
            l: self.num_filter_hashes * (self.num_filter_entries as f32).log2() as usize,
            n_hashes: self.num_filter_hashes,
            bits_per_hash: (self.num_filter_entries as f32).log2() as usize,
            bits_per_filter: self.num_filter_inputs,
        };
        WnnCircuit::new(hash_inputs, self.bloom_filters.clone(), params)
    }

    pub fn mock_proof(&self, image: &Array2<u8>, k: u32) {
        let input_bits = self.encode_image(image);
        let hash_inputs = self.compute_hash_inputs(input_bits.clone());
        let outputs: Vec<Fp> = self
            .predict(image)
            .iter()
            .map(|o| Fp::from(*o as u64))
            .collect();

        let circuit = self.get_circuit(hash_inputs);

        let prover = MockProver::run(k, &circuit, vec![outputs.clone()]).unwrap();
        prover.assert_satisfied();

        println!("Valid!");
        circuit.plot("real_wnn_layout.png", k);
    }

    /// Generate a proving key and verification key.
    ///
    /// The verification key can be accessed via `pk.get_vk()`.
    pub fn generate_proving_key(&self, kzg_params: &ParamsKZG<Bn256>) -> ProvingKey<G1Affine> {
        // They keys should not depend on the input, so we're generating a dummy input here
        let dummy_bits = (0..self.input_permutation.len()).map(|_| false).collect();
        let dummy_inputs = self.compute_hash_inputs(dummy_bits);

        let circuit = self.get_circuit(dummy_inputs);

        let vk = keygen_vk(kzg_params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(kzg_params, vk, &circuit).expect("keygen_pk should not fail");

        pk
    }

    /// Generate a proof for the given image.
    pub fn proof(
        &self,
        pk: &ProvingKey<G1Affine>,
        kzg_params: &ParamsKZG<Bn256>,
        image: &Array2<u8>,
    ) -> (Vec<u8>, Vec<Fp>) {
        let input_bits = self.encode_image(image);
        let hash_inputs = self.compute_hash_inputs(input_bits.clone());
        let outputs: Vec<Fp> = self
            .predict(image)
            .iter()
            .map(|o| Fp::from(*o as u64))
            .collect();

        let circuit = self.get_circuit(hash_inputs);

        let mut transcript: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>> =
            Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<Bn256>, _, _, _, _>(
            &kzg_params,
            &pk,
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
        proof: &Vec<u8>,
        kzg_params: &ParamsKZG<Bn256>,
        vk: &VerifyingKey<G1Affine>,
        outputs: &Vec<Fp>,
    ) {
        let transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&kzg_params);
        verify_proof::<_, VerifierGWC<Bn256>, _, _, _>(
            &kzg_params,
            vk,
            strategy.clone(),
            &[&[outputs.as_ref()]],
            &mut transcript.clone(),
        )
        .unwrap();
    }

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

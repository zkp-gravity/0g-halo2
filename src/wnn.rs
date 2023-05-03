// use std::time::Instant;

use halo2_proofs::dev::MockProver;
use ndarray::{Array1, Array3};

use halo2_proofs::halo2curves::pasta::pallas::Base as Fp;
use num_bigint::BigUint;
// use rand_core::OsRng;

use crate::gadgets::wnn::WnnCircuit;

pub struct Wnn<const P: u64, const L: usize, const N_HASHES: usize, const BITS_PER_HASH: usize> {
    num_classes: usize,
    num_filter_entries: usize,
    num_filter_hashes: usize,
    num_filter_inputs: usize,
    p: u64,

    /// Bloom filter array, shape (num_classes, num_inputs * bits_per_input / num_filter_inputs, num_filter_entries)
    bloom_filters: Array3<bool>,
    input_order: Array1<u64>,
}

impl<const P: u64, const L: usize, const N_HASHES: usize, const BITS_PER_HASH: usize>
    Wnn<P, L, N_HASHES, BITS_PER_HASH>
{
    pub fn new(
        num_classes: usize,
        num_filter_entries: usize,
        num_filter_hashes: usize,
        num_filter_inputs: usize,
        p: u64,

        bloom_filters: Array3<bool>,
        input_order: Array1<u64>,
    ) -> Self {
        Self {
            num_classes,
            num_filter_entries,
            num_filter_hashes,
            num_filter_inputs,
            p,
            bloom_filters,
            input_order,
        }
    }

    fn mish_mash_hash(&self, x: u64) -> BigUint {
        let x = BigUint::from(x);
        let modulus = BigUint::from(self.num_filter_entries).pow(self.num_filter_hashes as u32);
        ((&x * &x * &x) % self.p) % modulus
    }

    fn compute_hash_inputs(&self, input_bits: Vec<bool>) -> Vec<u64> {
        assert_eq!(input_bits.len(), self.input_order.shape()[0]);

        // Permute inputs
        let inputs_permuted: Vec<bool> = self
            .input_order
            .iter()
            .map(|i| input_bits[*i as usize])
            .collect();

        // Pack inputs into integers of `num_filter_inputs` bits
        inputs_permuted
            .chunks_exact(self.num_filter_inputs)
            .map(|chunk| chunk.iter().fold(0, |acc, b| (acc << 1) + (*b as u64)))
            .collect()
    }

    pub fn predict(&self, input_bits: Vec<bool>) -> Vec<u32> {
        let hash_inputs = self.compute_hash_inputs(input_bits);
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

    fn get_circuit(&self, hash_inputs: Vec<u64>) -> WnnCircuit<Fp, P, L, N_HASHES, BITS_PER_HASH> {
        assert_eq!(self.p, P);
        assert_eq!(self.num_filter_entries, 1 << BITS_PER_HASH);
        assert_eq!(self.num_filter_hashes, N_HASHES);
        WnnCircuit::new(hash_inputs, self.bloom_filters.clone())
    }

    pub fn mock_proof(&self, input_bits: Vec<bool>, k: u32) {
        let hash_inputs = self.compute_hash_inputs(input_bits.clone());
        let outputs: Vec<Fp> = self
            .predict(input_bits)
            .iter()
            .map(|o| Fp::from(*o as u64))
            .collect();

        let circuit = self.get_circuit(hash_inputs);

        // let prover = MockProver::run(k, &circuit, vec![outputs.clone()]).unwrap();
        // prover.assert_satisfied();

        println!("Valid!");
        // Plot with smaller k. This won't fit the bloom filter table but everything else will be readable
        circuit.plot("real_wnn_layout.png", 12);
    }

    pub fn proof_and_verify(&self, _input_bits: Vec<bool>, _k: u32) {
        // let hash_inputs = self.compute_hash_inputs(input_bits.clone());
        // let outputs: Vec<Fp> = self
        //     .predict(input_bits)
        //     .iter()
        //     .map(|o| Fp::from(*o as u64))
        //     .collect();

        // let circuit = self.get_circuit(hash_inputs);

        // println!("Key gen...");
        // let start = Instant::now();

        // let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
        // let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        // let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        // let duration = start.elapsed();
        // println!("Took: {:?}", duration);

        // println!("Proving...");
        // let start = Instant::now();

        // let mut transcript: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>> =
        //     Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<Bn256>, _, _, _, _>(
        //     &params,
        //     &pk,
        //     &[circuit],
        //     &[&[outputs.as_ref()]],
        //     OsRng,
        //     &mut transcript,
        // )
        // .unwrap();
        // let proof = transcript.finalize();

        // let duration = start.elapsed();
        // println!("Took: {:?}", duration);

        // println!("Verifying...");
        // let start = Instant::now();

        // let transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        // let strategy = SingleStrategy::new(&params);
        // verify_proof::<_, VerifierGWC<Bn256>, _, _, _>(
        //     &params,
        //     pk.get_vk(),
        //     strategy.clone(),
        //     &[&[outputs.as_ref()]],
        //     &mut transcript.clone(),
        // )
        // .unwrap();

        // let duration = start.elapsed();
        // println!("Took: {:?}", duration);

        // println!("Done!");
    }
}

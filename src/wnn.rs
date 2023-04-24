use ndarray::{Array1, Array3};
use num_bigint::BigUint;

pub struct Wnn {
    bits_per_input: usize,
    num_classes: usize,
    num_filter_entries: usize,
    num_filter_hashes: usize,
    num_filter_inputs: usize,
    num_inputs: usize,
    p: u64,

    bloom_filters: Array3<bool>,
    input_order: Array1<u64>,
}

impl Wnn {
    pub fn new(
        bits_per_input: usize,
        num_classes: usize,
        num_filter_entries: usize,
        num_filter_hashes: usize,
        num_filter_inputs: usize,
        num_inputs: usize,
        p: u64,

        bloom_filters: Array3<bool>,
        input_order: Array1<u64>,
    ) -> Self {
        Self {
            bits_per_input,
            num_classes,
            num_filter_entries,
            num_filter_hashes,
            num_filter_inputs,
            num_inputs,
            p,
            bloom_filters,
            input_order,
        }
    }

    fn mish_mash_hash(&self, x: BigUint) -> BigUint {
        let modulus = BigUint::from(self.num_filter_entries).pow(self.num_filter_hashes as u32);
        ((&x * &x * &x) % self.p) % modulus
    }

    pub fn predict(&self, input_bits: Vec<bool>) -> usize {
        assert_eq!(input_bits.len(), self.input_order.shape()[0]);

        // Permute inputs
        let inputs_permuted: Vec<bool> = self
            .input_order
            .iter()
            .map(|i| input_bits[*i as usize])
            .collect();

        // Pack inputs into integers of `num_filter_inputs` bits
        let hash_inputs: Vec<BigUint> = inputs_permuted
            .chunks_exact(self.num_filter_inputs)
            .map(|chunk| {
                chunk.iter().fold(BigUint::from(0u8), |acc, b| {
                    acc * 2u8 + BigUint::from(*b as usize)
                })
            })
            .collect();

        // Hash
        let hash_outputs: Vec<BigUint> = hash_inputs
            .into_iter()
            .map(|x| self.mish_mash_hash(x))
            .collect();

        // Split hashes
        // Look up bloom filter
        // Aggregate results
        todo!()
    }
}

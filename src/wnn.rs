use ndarray::{Array1, Array3};
use num_bigint::BigUint;

pub struct Wnn {
    num_classes: usize,
    num_filter_entries: usize,
    num_filter_hashes: usize,
    num_filter_inputs: usize,
    p: u64,

    /// Bloom filter array, shape (num_classes, num_inputs * bits_per_input / num_filter_inputs, num_filter_entries)
    bloom_filters: Array3<bool>,
    input_order: Array1<u64>,
}

impl Wnn {
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

    fn mish_mash_hash(&self, x: BigUint) -> BigUint {
        let modulus = BigUint::from(self.num_filter_entries).pow(self.num_filter_hashes as u32);
        ((&x * &x * &x) % self.p) % modulus
    }

    pub fn predict(&self, input_bits: Vec<bool>) -> Vec<u32> {
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
}

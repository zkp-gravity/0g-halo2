use ff::PrimeField;
use halo2_proofs::circuit::Value;
use num_bigint::BigUint;

#[allow(dead_code)]
pub(crate) fn print_value<F: PrimeField>(name: &str, value: Value<&F>) {
    value.map(|x| println!("{name}: {}", to_u32(x)));
}

#[allow(dead_code)]
pub(crate) fn print_values<F: PrimeField>(name: &str, values: &Vec<Value<F>>) {
    values.iter().for_each(|value| {
        value.map(|x| println!("{name}: {}", to_u32(&x)));
    });
}

pub(crate) fn integer_division<F: PrimeField>(x: F, divisor: BigUint) -> F {
    let x_bigint = BigUint::from_bytes_le(x.to_repr().as_ref());
    let quotient = x_bigint / divisor;

    // Convert from BigInt to F
    let bytes_be = quotient.to_bytes_be();
    let shift_factor = F::from(256);
    bytes_be
        .iter()
        .fold(F::ZERO, |acc, b| acc * shift_factor + F::from(*b as u64))
}

/// Implement to_le_bits for any `PrimeField` type, not just `PrimeFieldBits`
/// For example, the BN256 Fr type does not implement PrimeFieldBits
fn to_le_bits<F: PrimeField>(x: &F, n_bits: usize) -> Vec<bool> {
    // This assumes numbers are stored in little endian order
    let mut x = BigUint::from_bytes_le(x.to_repr().as_ref());

    let mut result = vec![];
    let zero = BigUint::from(0u8);
    let one = BigUint::from(1u8);
    for _ in 0..n_bits {
        result.push(if (&x & &one) == zero { false } else { true });
        x >>= 1;
    }

    result
}

pub(crate) fn decompose_word<F: PrimeField>(
    word: &F,
    num_windows: usize,
    window_num_bits: usize,
) -> Vec<F> {
    // Get bits in little endian order, select `word_num_bits` least significant bits
    let bits = to_le_bits(word, num_windows * window_num_bits);
    let two = F::from(2);

    bits.chunks_exact(window_num_bits)
        .map(|chunk| {
            chunk
                .iter()
                .rev()
                .fold(F::ZERO, |acc, b| acc * two + F::from(*b as u64))
        })
        .collect()
}

pub(crate) fn to_u32<F: PrimeField>(field_element: &F) -> u32 {
    to_le_bits(field_element, 32)
        .iter()
        .rev()
        .fold(0u32, |acc, b| (acc << 1) + (*b as u32))
}

#[cfg(test)]
mod tests {
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use num_bigint::BigUint;

    use crate::utils::{decompose_word, to_u32};

    use super::integer_division;

    #[test]
    fn test_decompose_word() {
        assert_eq!(decompose_word(&Fp::from(6), 1, 10), vec![Fp::from(6)]);
        assert_eq!(
            decompose_word(&Fp::from(0xabcdef), 2, 12),
            vec![Fp::from(0xdef), Fp::from(0xabc)]
        );
    }

    #[test]
    fn test_to_u64() {
        assert_eq!(to_u32(&Fp::from(6)), 6u32);
        assert_eq!(to_u32(&Fp::from(0x11223344u64)), 0x11223344u32);
    }

    #[test]
    fn test_integer_division() {
        assert_eq!(
            integer_division(Fp::from(6), BigUint::from(2u8)),
            Fp::from(3)
        );
        assert_eq!(
            integer_division(Fp::from(7), BigUint::from(2u8)),
            Fp::from(3)
        );
        assert_eq!(
            integer_division(-Fp::one(), BigUint::from(2u8)).double(),
            -Fp::one()
        );
    }
}

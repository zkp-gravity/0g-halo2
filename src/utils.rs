use std::ops::Range;

use ff::{PrimeField, PrimeFieldBits};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Error, Selector},
};
use num_bigint::BigUint;

#[allow(dead_code)]
pub fn print_value<F: PrimeFieldBits>(name: &str, value: Value<&F>) {
    value.map(|x| println!("{name}: {:#01x}", to_u32(x)));
}

#[allow(dead_code)]
pub fn print_values<F: PrimeFieldBits>(name: &str, values: &Vec<Value<F>>) {
    values.iter().for_each(|value| {
        value.map(|x| println!("{name}: {:#01x}", to_u32(&x)));
    });
}

pub fn enable_range<F: PrimeField>(
    region: &mut Region<F>,
    selector: Selector,
    range: Range<usize>,
) -> Result<(), Error> {
    for i in range {
        selector.enable(region, i)?;
    }
    Ok(())
}

pub fn argmax(vec: &Vec<u32>) -> usize {
    let mut index = 0;
    let mut max = 0;
    for (i, x) in vec.iter().enumerate() {
        if *x > max {
            max = *x;
            index = i;
        }
    }
    index
}

pub fn integer_division<F: PrimeField>(x: F, divisor: BigUint) -> F {
    let x_bigint = BigUint::from_bytes_le(x.to_repr().as_ref());
    let quotient = x_bigint / divisor;

    // Convert from BigInt to F
    let bytes_be = quotient.to_bytes_be();
    let shift_factor = F::from(256);
    bytes_be
        .iter()
        .fold(F::ZERO, |acc, b| acc * shift_factor + F::from(*b as u64))
}

/// Return the big-endian bits of `x` as a vector of `n_bits` (least significant) bits.
pub fn to_be_bits<F: PrimeFieldBits>(x: &F, n_bits: usize) -> Vec<bool> {
    let mut result = x
        .to_le_bits()
        .iter()
        .by_vals()
        .take(n_bits)
        .collect::<Vec<_>>();

    // Convert to big endian order
    result.reverse();

    result
}

pub fn from_be_bits<F: PrimeField>(bits: &[bool]) -> F {
    let mut result = F::ZERO;
    let two = F::from(2 as u64);
    for b in bits.iter() {
        result = result * two;
        if *b {
            result += F::ONE;
        }
    }
    result
}

pub fn decompose_word_be<F: PrimeFieldBits>(
    word: &F,
    num_windows: usize,
    window_num_bits: usize,
) -> Vec<F> {
    // Get bits in little endian order, select `word_num_bits` least significant bits
    let bits = to_be_bits(word, num_windows * window_num_bits);
    let two = F::from(2);

    bits.chunks_exact(window_num_bits)
        .map(|chunk| {
            chunk
                .iter()
                .fold(F::ZERO, |acc, b| acc * two + F::from(*b as u64))
        })
        .collect()
}

pub fn to_u32<F: PrimeFieldBits>(field_element: &F) -> u32 {
    to_be_bits(field_element, 32)
        .iter()
        .fold(0u32, |acc, b| (acc << 1) + (*b as u32))
}

#[cfg(test)]
mod tests {
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use num_bigint::BigUint;

    use crate::utils::{decompose_word_be, from_be_bits, to_be_bits, to_u32};

    use super::integer_division;

    #[test]
    fn test_to_be_bits() {
        assert_eq!(to_be_bits(&Fp::from(6), 4), vec![false, true, true, false]);
        assert_eq!(
            to_be_bits(&Fp::from(0x11223344u64), 32),
            vec![
                false, false, false, true, false, false, false, true, // Byte 1
                false, false, true, false, false, false, true, false, // Byte 2
                false, false, true, true, false, false, true, true, // Byte 3
                false, true, false, false, false, true, false, false // Byte 4
            ]
        );
    }

    #[test]
    fn test_from_be_bits() {
        assert_eq!(
            from_be_bits::<Fp>(&vec![false, true, true, false]),
            Fp::from(6)
        );
        assert_eq!(
            from_be_bits::<Fp>(&vec![
                false, false, false, true, false, false, false, true, // Byte 1
                false, false, true, false, false, false, true, false, // Byte 2
                false, false, true, true, false, false, true, true, // Byte 3
                false, true, false, false, false, true, false, false // Byte 4
            ]),
            Fp::from(0x11223344u64)
        );
    }

    #[test]
    fn test_decompose_word_be() {
        assert_eq!(decompose_word_be(&Fp::from(6), 1, 10), vec![Fp::from(6)]);
        assert_eq!(
            decompose_word_be(&Fp::from(0xabcdef), 2, 12),
            vec![Fp::from(0xabc), Fp::from(0xdef)]
        );
    }

    #[test]
    fn test_to_u32() {
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

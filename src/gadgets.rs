//! Collection of Halo2 gadgets.
//!
//! [`WnnChip`] is the main gadget for WNNs; [`WnnCircuit`] is the corresponding circuit.

pub mod bits2num;
pub mod bloom_filter;
pub mod encode_image;
pub mod greater_than;
pub mod hash;
pub mod range_check;
pub mod response_accumulator;
pub mod wnn;

pub use wnn::{WnnChip, WnnCircuit};

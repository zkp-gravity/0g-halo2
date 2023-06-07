//! Helper functions for deploying an EVM verifier contract and submitting proofs to it.
//!
//! # Example
//! ```
//! use std::path::Path;
//! use halo2_proofs::{
//!    halo2curves::bn256::Fr,
//!    poly::{
//!        commitment::ParamsProver,
//!        kzg::commitment::ParamsKZG,
//!    },
//! };
//! use zero_g::{
//!     checked_in_test_data::*,
//!     eth::{
//!         deploy::dry_run_verifier, gen_evm_verifier,
//!     },
//!     load_grayscale_image, load_wnn,
//! };
//!
//! // Load image and model
//! let img = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
//! let (k, model_path) = MNIST_TINY;
//! let wnn = load_wnn(Path::new(model_path)).unwrap();
//!
//! // Generate keys
//! let kzg_params = ParamsKZG::new(k);
//! let pk = wnn.generate_proving_key(&kzg_params);
//!
//! // Generate proof
//! let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);
//!
//! // Generate contract bytecode
//! let deployment_code = gen_evm_verifier(&kzg_params, pk.get_vk(), vec![outputs.len()]);
//!
//! // Verify the proof using the EVM verifier
//! let gas_used = dry_run_verifier(deployment_code, vec![outputs], proof).unwrap();
//! ```

pub mod deploy;
pub mod vanilla_plonk_circuit;

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use snark_verifier::{
    loader::evm::{self, EvmLoader},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{plonk::PlonkVerifier, SnarkVerifier},
};
use std::rc::Rc;

/// Generates EVM bytecode for a verifier contract.
pub fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );

    println!(
        "Verification key: Number of fixed commitments: {}",
        vk.fixed_commitments().len()
    );

    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::<KzgAs<Bn256, Gwc19>>::read_proof(
        &vk,
        &protocol,
        &instances,
        &mut transcript,
    )
    .unwrap();
    PlonkVerifier::<KzgAs<Bn256, Gwc19>>::verify(&vk, &protocol, &instances, &proof).unwrap();

    let yul_code = loader.yul_code();
    let bytecode = evm::compile_yul(&yul_code);

    println!("Byte code size: {}", bytecode.len());

    bytecode
}

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

use ethers::{
    abi::Abi,
    contract::ContractFactory,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, TransactionReceipt, TransactionRequest},
};
use eyre::{eyre, Result};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use snark_verifier::loader::evm::encode_calldata;
use snark_verifier::loader::evm::ExecutorBuilder;
use snark_verifier::{
    loader::evm::{self, EvmLoader},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{plonk::PlonkVerifier, SnarkVerifier},
};
use std::rc::Rc;
use std::{sync::Arc, time::Duration};

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

/// Dry runs a given EVM contract locally using `revm`, returning the gas used.
pub fn dry_run_verifier(
    deployment_code: Vec<u8>,
    instances: Vec<Vec<Fr>>,
    proof: Vec<u8>,
) -> Result<u64> {
    let calldata = encode_calldata(&instances, &proof);
    let mut evm = ExecutorBuilder::default()
        .with_gas_limit(u64::MAX.into())
        .build();

    let caller = Address::from_low_u64_be(0xfe);
    let deployment_result = evm.deploy(caller, deployment_code.into(), 0.into());

    let verifier = deployment_result.address;
    match verifier {
        Some(verifier) => {
            let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

            if !result.reverted {
                Ok(result.gas_used)
            } else {
                Err(eyre!("Verifier reverted"))
            }
        }
        None => Err(eyre!(
            "Verifier deployment failed: {:?}",
            deployment_result.exit_reason
        )),
    }
}

fn print_receipt(receipt: TransactionReceipt) {
    println!("== Transaction summary");
    println!("  Transaction hash: {:?}", receipt.transaction_hash);
    println!("  Deployed at block: {:?}", receipt.block_number);
    println!("  Gas used: {:?}", receipt.gas_used.unwrap());
}

/// Deploys an EVM contract.
pub async fn deploy_contract(
    endpoint: String,
    wallet: LocalWallet,
    deployment_code: Vec<u8>,
) -> Result<Address> {
    let provider = Provider::<Http>::try_from(endpoint)?.interval(Duration::from_millis(10u64));
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));
    let client = Arc::new(client);

    let factory = ContractFactory::new(Abi::default(), deployment_code.into(), client.clone());

    let (contract, deploy_receipt) = factory.deploy(())?.send_with_receipt().await?;
    print_receipt(deploy_receipt);
    println!("Deployed to address: {:?}", contract.address());

    Ok(contract.address())
}

/// Submits a proof to an EVM contract.
pub async fn submit_proof(
    endpoint: String,
    wallet: LocalWallet,
    contract_address: Address,
    proof: Vec<u8>,
    instances: Vec<Vec<Fr>>,
) -> Result<()> {
    let provider = Provider::<Http>::try_from(endpoint)?.interval(Duration::from_millis(10u64));
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));
    let client = Arc::new(client);

    let calldata = encode_calldata(&instances, &proof);

    let tx = TransactionRequest::new()
        .to(contract_address)
        .data(calldata);
    let receipt = client
        .send_transaction(tx, None)
        .await?
        .await?
        .ok_or(eyre!("No receipt!"))?;

    print_receipt(receipt);

    Ok(())
}

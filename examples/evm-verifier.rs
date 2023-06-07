use ethers::{
    signers::{LocalWallet, Signer},
    utils::Anvil,
};
use eyre::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use std::{env, path::Path, str::FromStr};
use zero_g::{
    checked_in_test_data::*,
    eth::{deploy_contract, dry_run_verifier, gen_evm_verifier, submit_proof},
    load_grayscale_image, load_wnn,
};

async fn validate_evm(
    kzg_params: ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: Vec<u8>,
    instances: Vec<Vec<Fr>>,
    endpoint: Option<&String>,
) {
    println!("Generating deployment code...");
    let deployment_code = gen_evm_verifier(&kzg_params, vk, vec![instances[0].len()]);

    println!("Verifying proof...");
    let gas_used =
        dry_run_verifier(deployment_code.clone(), instances.clone(), proof.clone()).unwrap();
    println!("Gas used: {}", gas_used);

    if let Some(endpoint) = endpoint {
        let anvil = Anvil::new().spawn();

        let (endpoint, wallet) = if endpoint == "anvil" {
            (anvil.endpoint(), anvil.keys()[0].clone().into())
        } else {
            let private_key = env::var("ETH_PRIVATE_KEY").expect("ETH_PRIVATE_KEY is not set");
            (
                endpoint.clone(),
                LocalWallet::from_str(&private_key).unwrap(),
            )
        };

        println!("Address: {:?}", wallet.address());

        println!("Deploying...");
        let contract_address = deploy_contract(endpoint.clone(), wallet.clone(), deployment_code)
            .await
            .unwrap();

        println!("Submitting proof...");
        submit_proof(endpoint, wallet, contract_address, proof, instances)
            .await
            .unwrap();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let (k, model_path) = MNIST_MEDIUM;

    let wnn = load_wnn(Path::new(model_path)).unwrap();
    let image = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();

    let kzg_params = ParamsKZG::<Bn256>::new(k);
    let pk = wnn.generate_proving_key(&kzg_params);
    let (proof, instance_column) = wnn.proof(&pk, &kzg_params, &image);

    validate_evm(
        kzg_params,
        pk.get_vk(),
        proof,
        vec![instance_column],
        args.get(1),
    )
    .await;
    Ok(())
}

use eyre::Result;
use halo2_proofs::{halo2curves::bn256::Fr, plonk::Circuit};
use rand::rngs::OsRng;
use std::{env, path::Path};
use zero_g::{
    checked_in_test_data::*,
    eth::{
        deploy::{evm_deploy, evm_verify},
        gen_evm_verifier, gen_pk, gen_proof, gen_srs,
        vanilla_plonk_circuit::StandardPlonk,
    },
    load_grayscale_image, load_wnn,
};

async fn validate_evm<C: Circuit<Fr> + Clone>(
    circuit: C,
    instances: Vec<Vec<Fr>>,
    k: u32,
    name: &str,
    deploy: bool,
) {
    println!("Generating Params...");
    let params = gen_srs(k);
    println!("Generating PK...");
    let pk = gen_pk(&params, &circuit);
    println!("Generating deployment code...");
    let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![instances[0].len()], name);

    println!("Generating proof...");
    let proof = gen_proof(&params, &pk, circuit.clone(), instances.clone());

    println!("Verifying proof...");
    evm_verify(deployment_code.clone(), instances.clone(), proof.clone());

    if deploy {
        println!("Deploying...");
        evm_deploy(deployment_code, instances.clone(), proof)
            .await
            .unwrap();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args[1] == "wnn" {
        let (k, model_path) = MNIST_MEDIUM;

        let wnn = load_wnn(Path::new(model_path)).unwrap();
        let image = load_grayscale_image(Path::new(TEST_IMG_PATH)).unwrap();
        let circuit = wnn.get_circuit(&image);

        let outputs: Vec<Fr> = wnn.predict(&image).into_iter().map(Fr::from).collect();
        let instances = vec![outputs];
        validate_evm(circuit, instances, k, &args[1], args.len() > 2).await;
    } else if args[1] == "plonk" {
        let circuit = StandardPlonk::rand(OsRng);
        let instances = circuit.instances();
        let k = 8;

        validate_evm(circuit, instances, k, &args[1], args.len() > 2).await;
    } else {
        panic!("Unknown circuit: {:?}", args[1]);
    }
    Ok(())
}

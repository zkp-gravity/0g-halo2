use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use ethers::types::Address;
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use hdf5::Result;
use hex;
use indicatif::ProgressIterator;
use zero_g::{
    eth::{dry_run_verifier, gen_evm_verifier, EthClient},
    io::{
        parse_png_file, read_circuit_params, read_pk, read_srs, read_vk, write_circuit_params,
        write_keys, write_srs, ProofWithOutput,
    },
    load_grayscale_image, load_wnn,
    utils::argmax,
    Wnn,
};

#[derive(Parser)]
#[clap(name = "Zero G")]
#[clap(version)]
#[clap(author)]
#[clap(about)]
struct Arguments {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Predict inference of a particular image (no proving)
    Predict {
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// Path to the image (e.g. benches/example_image_7.png)
        #[clap(short, long)]
        img_path: PathBuf,
    },
    /// Compute the accuracy on the test set
    ComputeAccuracy {
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// Path to the test set (e.g. data/MNIST/png)
        #[clap(short, long)]
        test_set_path: PathBuf,
    },
    /// Step 0: Mock proof inference of a particular image. This can be helpful to figure out the
    /// right value of `k` and to test the correctness of the circuit.
    MockProof {
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// Path to the image (e.g. benches/example_image_7.png)
        #[clap(short, long)]
        img_path: PathBuf,
        /// The value `k` used for the powers of tau. The size of the SRS will be `2^k`.
        #[clap(short, long)]
        k: u32,
    },
    /// Step 1: Generate the SRS
    GenerateSrs {
        /// The value `k` used for the powers of tau. The size of the SRS will be `2^k`.
        #[clap(short, long)]
        k: u32,
        /// Path to write the SRS to
        #[clap(short, long)]
        srs_path: PathBuf,
    },
    /// Step 2: Generate the proving and verifying keys
    GenerateKeys {
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// Path to read the SRS from
        #[clap(short, long)]
        srs_path: PathBuf,
        /// Path to write the verifying key to
        #[clap(short, long)]
        vk_path: PathBuf,
        /// Path to write the proving key to
        #[clap(short, long)]
        pk_path: PathBuf,
        /// Path to write the circuit params to
        #[clap(short, long)]
        circuit_params_path: PathBuf,
    },
    /// Step 2.1: Generate the EVM verifier and run a test proof
    DryRunEvmVerifier {
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// Path to the image (e.g. benches/example_image_7.png)
        #[clap(short, long)]
        img_path: PathBuf,
        /// Path to read the SRS from
        #[clap(short, long)]
        srs_path: PathBuf,
        /// Path to read the proving key from (used to simulate test a proof and extract the verifying key)
        #[clap(short, long)]
        pk_path: PathBuf,
    },
    /// Step 2.2: Generate the EVM verifier
    DeployEvmVerifier {
        /// Path to read the SRS from
        #[clap(short, long)]
        srs_path: PathBuf,
        /// Path to read the verifying key from
        #[clap(short, long)]
        vk_path: PathBuf,
        /// Path to read the circuit params from
        #[clap(short, long)]
        circuit_params_path: PathBuf,
        /// The HTTP endpoint to the chain, or "anvil" to use the Anvil testnet.
        /// If not "anvil", the "ETH_PRIVATE_KEY" must be set to your private key.
        #[clap(default_value_t = String::from("anvil"), short, long)]
        endpoint: String,
    },
    /// Step 3: Proof inference of a particular image
    Proof {
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// Path to the image (e.g. benches/example_image_7.png)
        #[clap(short, long)]
        img_path: PathBuf,
        /// Path to read the SRS from
        #[clap(short, long)]
        srs_path: PathBuf,
        /// Path to read the proving key from
        #[clap(short, long)]
        pk_path: PathBuf,
        /// Path to store the proof to
        #[clap(short, long)]
        proof_path: PathBuf,
    },
    /// Step 4: Verify the proof
    Verify {
        /// Path to read the SRS from
        #[clap(short, long)]
        srs_path: PathBuf,
        /// Path to read the verifying key from
        #[clap(short, long)]
        vk_path: PathBuf,
        /// Path to read the circuit params from
        #[clap(short, long)]
        circuit_params_path: PathBuf,
        /// Path to read the proof from
        #[clap(short, long)]
        proof_path: PathBuf,
    },
    /// Step 4.1: Submit the proof to the EVM verifier
    SubmitProof {
        /// Path to read the proof from
        #[clap(short, long)]
        proof_path: PathBuf,
        /// Contract address (e.g. 0x5fbdb2315678afecb367f032d93f642f64180aa3)
        #[clap(short, long)]
        contract_address: String,
        /// The HTTP endpoint to the chain, or "anvil" to use the Anvil testnet.
        /// If not "anvil", the "ETH_PRIVATE_KEY" must be set to your private key.
        #[clap(default_value_t = String::from("anvil"), short, long)]
        endpoint: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Arguments = Arguments::parse();

    match args.command {
        Commands::Predict {
            model_path,
            img_path,
        } => {
            let wnn = load_wnn(&model_path)?;
            let img = load_grayscale_image(&img_path).unwrap();
            println!("{:?}", wnn.predict(&img));

            Ok(())
        }
        Commands::ComputeAccuracy {
            model_path,
            test_set_path,
        } => {
            let wnn = load_wnn(&model_path)?;

            let mut correct = 0;
            let mut total = 0;

            let dir_entries: Vec<_> = fs::read_dir(test_set_path).unwrap().collect();
            for dir_entry in dir_entries.into_iter().progress() {
                let img_path = dir_entry.unwrap().path();

                if let Some(correct_class) = parse_png_file(&img_path) {
                    let img = load_grayscale_image(&img_path).unwrap();
                    let scores = wnn.predict(&img);
                    let prediction = argmax(&scores);

                    if prediction == correct_class {
                        correct += 1;
                    }
                    total += 1;
                }
            }

            println!("Accuracy: {} / {}", correct, total);

            Ok(())
        }
        Commands::MockProof {
            model_path,
            img_path,
            k,
        } => {
            let wnn = load_wnn(&model_path)?;
            let img = load_grayscale_image(&img_path).unwrap();
            println!("Prediction: {:?}", wnn.predict(&img));

            println!("Verifying constraints...");
            wnn.mock_proof(&img, k);
            println!("Valid!");

            wnn.plot_circuit("real_wnn_layout.png", k);
            Ok(())
        }
        Commands::GenerateSrs { k, srs_path } => {
            let srs = ParamsKZG::<Bn256>::new(k);
            write_srs(&srs, &srs_path);
            Ok(())
        }
        Commands::GenerateKeys {
            model_path,
            srs_path,
            vk_path,
            pk_path,
            circuit_params_path,
        } => {
            let wnn = load_wnn(&model_path)?;
            let kzg_params = read_srs(&srs_path);
            let pk = wnn.generate_proving_key(&kzg_params);
            write_keys(&pk, &pk_path, &vk_path);
            write_circuit_params(&wnn.get_circuit_params(), &circuit_params_path);
            Ok(())
        }
        Commands::DryRunEvmVerifier {
            model_path,
            img_path,
            srs_path,
            pk_path,
        } => {
            let img = load_grayscale_image(&img_path).unwrap();
            let wnn = load_wnn(&model_path).unwrap();

            let kzg_params = read_srs(&srs_path);
            let pk = read_pk(&pk_path, wnn.get_circuit_params());

            println!("Generating proof...");
            let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);

            println!("Generating EVM verifier...");
            let deployment_code = gen_evm_verifier(&kzg_params, pk.get_vk(), vec![outputs.len()]);

            println!("Dry-running EVM verifier...");
            let gas_used = dry_run_verifier(deployment_code, vec![outputs], proof).unwrap();
            println!("=> Gas used: {}", gas_used);
            Ok(())
        }
        Commands::DeployEvmVerifier {
            srs_path,
            vk_path,
            circuit_params_path,
            endpoint,
        } => {
            let kzg_params = read_srs(&srs_path);
            let circuit_params = read_circuit_params(&circuit_params_path);
            let n_classes = circuit_params.n_classes;
            let vk = read_vk(&vk_path, circuit_params);

            println!("Generating EVM verifier...");
            let deployment_code = gen_evm_verifier(&kzg_params, &vk, vec![n_classes]);

            let client = EthClient::new(endpoint)
                .await
                .expect("Error creating client");

            println!("Address: {:?}", client.address);

            println!("Deploying...");
            let contract_address = client.deploy_contract(deployment_code).await.unwrap();
            println!("Contract address: {:?}", contract_address);
            Ok(())
        }
        Commands::Proof {
            model_path,
            img_path,
            srs_path,
            pk_path,
            proof_path,
        } => {
            let wnn = load_wnn(&model_path)?;
            let img = load_grayscale_image(&img_path).unwrap();

            let kzg_params = read_srs(&srs_path);
            let pk = read_pk(&pk_path, wnn.get_circuit_params());

            ProofWithOutput::from(wnn.proof(&pk, &kzg_params, &img)).write(&proof_path);
            Ok(())
        }
        Commands::Verify {
            srs_path,
            vk_path,
            circuit_params_path,
            proof_path,
        } => {
            let kzg_params = read_srs(&srs_path);
            let circuit_params = read_circuit_params(&circuit_params_path);
            let vk = read_vk(&vk_path, circuit_params);
            let (proof, outputs) = ProofWithOutput::read(&proof_path).into();

            Wnn::verify_proof(&proof, &kzg_params, &vk, &outputs);
            Ok(())
        }
        Commands::SubmitProof {
            proof_path,
            mut contract_address,
            endpoint,
        } => {
            let (proof, outputs) = ProofWithOutput::read(&proof_path).into();

            let client = EthClient::new(endpoint)
                .await
                .expect("Error creating client");

            // Parse contract address
            if contract_address.starts_with("0x") {
                contract_address = contract_address[2..].to_string();
            }
            let contract_address = hex::decode(contract_address).expect("Invalid contract address");
            let contract_address = Address::from_slice(&contract_address);

            client
                .submit_proof(contract_address, proof, vec![outputs])
                .await
                .unwrap();

            Ok(())
        }
    }
}

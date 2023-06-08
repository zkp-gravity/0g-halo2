use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use hdf5::Result;
use indicatif::ProgressIterator;
use zero_g::{
    eth::{dry_run_verifier, gen_evm_verifier, EthClient},
    io::parse_png_file,
    load_grayscale_image, load_wnn,
    utils::argmax,
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
        // TODO: Store SRS at srs_path
        /// The value `k` used for the powers of tau. The size of the SRS will be `2^k`.
        #[clap(short, long)]
        k: u32,
    },
    /// Step 2: Generate the proving and verifying keys
    GenerateKeys {
        // TODO: Remove k; add srs_path
        // TODO: Store vk (with SRS) at vk_path, store pk (with SRS) at pk_path
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// The value `k` used for the powers of tau. The size of the SRS will be `2^k`.
        #[clap(short, long)]
        k: u32,
    },
    /// Step 2.1: Generate the EVM verifier and run a test proof
    DryRunEvmVerifier {
        // TODO: Remove k; add pk_path
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
    /// Step 2.2: Generate the EVM verifier
    DeployEvmVerifier {
        // TODO: Remove k; add vk_path
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// The value `k` used for the powers of tau. The size of the SRS will be `2^k`.
        #[clap(short, long)]
        k: u32,
        /// The HTTP endpoint to the chain, or "anvil" to use the Anvil testnet.
        /// If not "anvil", the "ETH_PRIVATE_KEY" must be set to your private key.
        #[clap(default_value_t = String::from("anvil"), short, long)]
        endpoint: String,
    },
    /// Step 3: Proof inference of a particular image
    Proof {
        // TODO: Remove k; add pk_path
        // TODO: Store proof (with instance) at proof_path
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
    /// Step 4: Verify the proof
    Verify {
        // TODO: Remove model_path, k & img_path; add vk_path & proof_path
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
    /// Step 4.1: Submit the proof to the EVM verifier
    SubmitProof {
        // TODO: Remove model_path, img_path, k; add proof_path and conract_address
        /// Path to the model (e.g. models/model_28input_2048entry_2hash_3bpi.hdf5)
        #[clap(short, long)]
        model_path: PathBuf,
        /// Path to the image (e.g. benches/example_image_7.png)
        #[clap(short, long)]
        img_path: PathBuf,
        /// The value `k` used for the powers of tau. The size of the SRS will be `2^k`.
        #[clap(short, long)]
        k: u32,
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
        Commands::GenerateSrs { k } => {
            ParamsKZG::<Bn256>::new(k);
            Ok(())
        }
        Commands::GenerateKeys { model_path, k } => {
            let wnn = load_wnn(&model_path)?;
            let kzg_params = ParamsKZG::<Bn256>::new(k);
            wnn.generate_proving_key(&kzg_params);
            Ok(())
        }
        Commands::DryRunEvmVerifier {
            model_path,
            img_path,
            k,
        } => {
            let img = load_grayscale_image(&img_path).unwrap();
            let wnn = load_wnn(&model_path).unwrap();

            println!("Generating keys...");
            let kzg_params = ParamsKZG::new(k);
            let pk = wnn.generate_proving_key(&kzg_params);

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
            model_path,
            k,
            endpoint,
        } => {
            let wnn = load_wnn(&model_path).unwrap();

            println!("Generating keys...");
            let kzg_params = ParamsKZG::new(k);
            let pk = wnn.generate_proving_key(&kzg_params);

            println!("Generating EVM verifier...");
            let deployment_code = gen_evm_verifier(&kzg_params, pk.get_vk(), vec![wnn.num_classes]);

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
            k,
        } => {
            let wnn = load_wnn(&model_path)?;
            let img = load_grayscale_image(&img_path).unwrap();

            let kzg_params = ParamsKZG::<Bn256>::new(k);
            let pk = wnn.generate_proving_key(&kzg_params);

            let (_proof, _outputs) = wnn.proof(&pk, &kzg_params, &img);
            Ok(())
        }
        Commands::Verify {
            model_path,
            img_path,
            k,
        } => {
            let wnn = load_wnn(&model_path)?;
            let img = load_grayscale_image(&img_path).unwrap();

            let kzg_params = ParamsKZG::<Bn256>::new(k);
            let pk = wnn.generate_proving_key(&kzg_params);
            let vk = pk.get_vk();

            let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);

            wnn.verify_proof(&proof, &kzg_params, vk, &outputs);
            Ok(())
        }
        Commands::SubmitProof {
            model_path,
            img_path,
            k,
            endpoint,
        } => {
            let img = load_grayscale_image(&img_path).unwrap();
            let wnn = load_wnn(&model_path).unwrap();

            let kzg_params = ParamsKZG::new(k);
            let pk = wnn.generate_proving_key(&kzg_params);
            let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);
            let deployment_code = gen_evm_verifier(&kzg_params, pk.get_vk(), vec![outputs.len()]);

            let client = EthClient::new(endpoint)
                .await
                .expect("Error creating client");
            let contract_address = client.deploy_contract(deployment_code).await.unwrap();

            client
                .submit_proof(contract_address, proof, vec![outputs])
                .await
                .unwrap();

            Ok(())
        }
    }
}

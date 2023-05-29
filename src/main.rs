use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use hdf5::Result;
use indicatif::ProgressIterator;
use zero_g::{load_image, load_wnn, utils::argmax};

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
    /// Proof inference of a particular image
    Proof {
        model_path: PathBuf,
        img_path: PathBuf,
        k: u32,
    },
    /// Predict inference of a particular image (no proving)
    Predict {
        model_path: PathBuf,
        img_path: PathBuf,
    },
    /// Compute the accuracy on the test set (in data/MNIST/png)
    ComputeAccuracy { model_path: PathBuf },
}

fn parse_png_file(img_path: &Path) -> Option<usize> {
    match img_path.extension() {
        Some(extension) => {
            if extension == "png" {
                Some(
                    img_path
                        .file_stem()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .chars()
                        .last()
                        .unwrap()
                        .to_digit(10)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

fn main() -> Result<()> {
    let args: Arguments = Arguments::parse();

    match args.command {
        Commands::Proof {
            model_path,
            img_path,
            k,
        } => {
            let wnn = load_wnn(&model_path)?;
            let img = load_image(&img_path).unwrap();
            println!("Prediction: {:?}", wnn.predict(&img));

            println!("Verifying constraints...");
            wnn.mock_proof(&img, k);

            println!("Proving...");
            wnn.proof_and_verify(&img, k);

            Ok(())
        }
        Commands::Predict {
            model_path,
            img_path,
        } => {
            let wnn = load_wnn(&model_path)?;
            let img = load_image(&img_path).unwrap();
            println!("{:?}", wnn.predict(&img));

            Ok(())
        }
        Commands::ComputeAccuracy { model_path } => {
            let wnn = load_wnn(&model_path)?;

            let mut correct = 0;
            let mut total = 0;

            let dir_entries: Vec<_> = fs::read_dir("data/MNIST/png").unwrap().collect();
            for dir_entry in dir_entries.into_iter().progress() {
                let img_path = dir_entry.unwrap().path();

                if let Some(correct_class) = parse_png_file(&img_path) {
                    let img = load_image(&img_path).unwrap();
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
    }
}

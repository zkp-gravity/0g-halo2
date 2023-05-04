use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use hdf5::Result;
use indicatif::ProgressIterator;
use zero_g::{
    io::{image::load_image, model::load_wnn},
    utils::argmax,
    wnn::Wnn,
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
    /// Proof inference of a particular image
    Proof { img_path: PathBuf },
    /// Predict inference of a particular image (no proving)
    Predict { img_path: PathBuf },
    /// Compute the accuracy on the test set (in data/MNIST/png)
    ComputeAccuracy,
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

    let wnn: Wnn<2097143, 20, 2, 10> =
        load_wnn("models/model_28input_1024entry_2hash_2bpi.pickle.hdf5")?;
    // let wnn: Wnn<509, 8, 1, 8> = load_wnn("models/model_28input_256entry_1hash_1bpi.pickle.hdf5")?;

    match args.command {
        Commands::Proof { img_path } => {
            let img = load_image(img_path).unwrap();
            println!("{:?}", wnn.predict(&img));

            wnn.mock_proof(&img, 20);
            wnn.proof_and_verify(&img, 20);

            Ok(())
        }
        Commands::Predict { img_path } => {
            let img = load_image(img_path).unwrap();
            println!("{:?}", wnn.predict(&img));

            Ok(())
        }
        Commands::ComputeAccuracy => {
            let mut correct = 0;
            let mut total = 0;

            let dir_entries: Vec<_> = fs::read_dir("data/MNIST/png").unwrap().collect();
            for dir_entry in dir_entries.into_iter().progress() {
                let img_path = dir_entry.unwrap().path();

                if let Some(correct_class) = parse_png_file(&img_path) {
                    let img = load_image(img_path).unwrap();
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

use clap::{Parser, Subcommand};
use hdf5::Result;
use zero_g::{io::model::load_wnn, wnn::Wnn};

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
    DummyProof {},
}

fn main() -> Result<()> {
    let args: Arguments = Arguments::parse();

    match args.command {
        Commands::DummyProof {} => {
            // let wnn: Wnn<2097143, 20, 2, 10> =
            //     load_wnn("models/model_28input_1024entry_2hash_2bpi.pickle.hdf5")?;
            let wnn: Wnn<509, 8, 1, 8> =
                load_wnn("models/model_28input_256entry_1hash_1bpi.pickle.hdf5")?;

            let input_bits =
                Vec::from((0..wnn.num_input_bits()).map(|_| false).collect::<Vec<_>>());
            println!("{:?}", wnn.predict(input_bits.clone()));

            wnn.mock_proof(input_bits.clone(), 20);
            wnn.proof_and_verify(input_bits, 20);

            Ok(())
        }
    }
}

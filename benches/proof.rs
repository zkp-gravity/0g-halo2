use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion};
use zero_g::io::{image::load_image, model::load_wnn};

fn criterion_benchmark(c: &mut Criterion) {
    let model_path = PathBuf::from("models/model_28input_256entry_1hash_1bpi.pickle.hdf5");
    let img_path = PathBuf::from("benches/example_image_7.png");

    let wnn = load_wnn(&model_path).unwrap();
    let img = load_image(&img_path).unwrap();

    let k = 12;

    c.bench_function("proof_and_verify", |b| {
        b.iter(|| wnn.proof_and_verify(&img, k))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

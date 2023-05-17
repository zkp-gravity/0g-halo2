use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use ndarray::Array2;
use zero_g::{
    io::{image::load_image, model::load_wnn},
    wnn::Wnn,
};

fn setup() -> (Wnn, Array2<u8>, u32) {
    let model_path = PathBuf::from("models/model_28input_256entry_1hash_1bpi.pickle.hdf5");
    let img_path = PathBuf::from("benches/example_image_7.png");

    let wnn = load_wnn(&model_path).unwrap();
    let img = load_image(&img_path).unwrap();

    let k = 12;

    (wnn, img, k)
}

fn bench_key_generation(b: &mut Bencher) {
    let (wnn, _img, k) = setup();

    b.iter(|| wnn.generate_proving_key(k));
}

fn bench_proof_generation(b: &mut Bencher) {
    let (wnn, img, k) = setup();

    let (pk, kzg_params) = wnn.generate_proving_key(k);

    b.iter(|| wnn.proof(&pk, &kzg_params, &img));
}

fn bench_verification(b: &mut Bencher) {
    let (wnn, img, k) = setup();

    let (pk, kzg_params) = wnn.generate_proving_key(k);
    let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);

    b.iter(|| wnn.verify_proof(&proof, &kzg_params, &pk, &outputs));
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("benches");
    group.sample_size(10);

    group.bench_function("proof_generation", bench_proof_generation);
    group.bench_function("key_generation", bench_key_generation);
    group.bench_function("verification", bench_verification);

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use ndarray::Array2;
use zero_g::{load_grayscale_image, load_wnn, Wnn};

fn setup() -> (Wnn, Array2<u8>, ParamsKZG<Bn256>) {
    let model_path = PathBuf::from("models/model_28input_256entry_1hash_1bpi.hdf5");
    let img_path = PathBuf::from("benches/example_image_7.png");

    let wnn = load_wnn(&model_path).unwrap();
    let img = load_grayscale_image(&img_path).unwrap();

    let kzg_params = ParamsKZG::new(12);

    (wnn, img, kzg_params)
}

fn bench_key_generation(b: &mut Bencher) {
    let (wnn, _img, kzg_params) = setup();

    b.iter(|| wnn.generate_proving_key(&kzg_params));
}

fn bench_proof_generation(b: &mut Bencher) {
    let (wnn, img, kzg_params) = setup();

    let pk = wnn.generate_proving_key(&kzg_params);

    b.iter(|| wnn.proof(&pk, &kzg_params, &img));
}

fn bench_verification(b: &mut Bencher) {
    let (wnn, img, kzg_params) = setup();

    let pk = wnn.generate_proving_key(&kzg_params);
    let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);

    b.iter(|| wnn.verify_proof(&proof, &kzg_params, pk.get_vk(), &outputs));
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

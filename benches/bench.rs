use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use ndarray::Array2;
use zero_g::{checked_in_test_data::*, load_grayscale_image, load_wnn, Wnn};

fn setup(model_info: (u32, &str)) -> (Wnn, Array2<u8>, ParamsKZG<Bn256>) {
    let (k, model_path) = model_info;
    let model_path = PathBuf::from(model_path);
    let img_path = PathBuf::from(TEST_IMG_PATH);

    let wnn = load_wnn(&model_path).unwrap();
    let img = load_grayscale_image(&img_path).unwrap();

    let kzg_params = ParamsKZG::new(k);

    (wnn, img, kzg_params)
}

fn bench_key_generation(b: &mut Bencher, model_info: (u32, &str)) {
    let (wnn, _img, kzg_params) = setup(model_info);

    b.iter(|| wnn.generate_proving_key(&kzg_params));
}

fn bench_proof_generation(b: &mut Bencher, model_info: (u32, &str)) {
    let (wnn, img, kzg_params) = setup(model_info);

    let pk = wnn.generate_proving_key(&kzg_params);

    b.iter(|| wnn.proof(&pk, &kzg_params, &img));
}

fn bench_verification(b: &mut Bencher, model_info: (u32, &str)) {
    let (wnn, img, kzg_params) = setup(model_info);

    let pk = wnn.generate_proving_key(&kzg_params);
    let (proof, outputs) = wnn.proof(&pk, &kzg_params, &img);

    b.iter(|| Wnn::verify_proof(&proof, &kzg_params, pk.get_vk(), &outputs));
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("benches");
    group.sample_size(10);

    group.bench_function("key_generation_mnist_tiny", |b| {
        bench_key_generation(b, MNIST_TINY)
    });
    group.bench_function("proof_generation_mnist_tiny", |b| {
        bench_proof_generation(b, MNIST_TINY)
    });
    group.bench_function("verification_mnist_tiny", |b| {
        bench_verification(b, MNIST_TINY)
    });

    group.bench_function("proof_generation_mnist_small", |b| {
        bench_proof_generation(b, MNIST_SMALL)
    });
    group.bench_function("verification_mnist_small", |b| {
        bench_verification(b, MNIST_SMALL)
    });

    group.bench_function("proof_generation_mnist_medium", |b| {
        bench_proof_generation(b, MNIST_MEDIUM)
    });
    group.bench_function("verification_mnist_medium", |b| {
        bench_verification(b, MNIST_MEDIUM)
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

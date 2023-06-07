use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::Field,
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error,
        Fixed, Instance, ProvingKey,
    },
    poly::{
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverGWC,
        },
        Rotation,
    },
    transcript::TranscriptWriterBuffer,
};
use itertools::Itertools;
use rand::RngCore;
use rand_core::OsRng;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;

#[derive(Clone, Copy)]
pub struct StandardPlonkConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    q_a: Column<Fixed>,
    q_b: Column<Fixed>,
    q_c: Column<Fixed>,
    q_ab: Column<Fixed>,
    constant: Column<Fixed>,
    #[allow(dead_code)]
    instance: Column<Instance>,
}

impl StandardPlonkConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let [a, b, c] = [(); 3].map(|_| meta.advice_column());
        let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
        let instance = meta.instance_column();

        [a, b, c].map(|column| meta.enable_equality(column));

        meta.create_gate(
            "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
            |meta| {
                let [a, b, c] = [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                    .map(|column| meta.query_fixed(column, Rotation::cur()));
                let instance = meta.query_instance(instance, Rotation::cur());
                Some(
                    q_a * a.clone()
                        + q_b * b.clone()
                        + q_c * c
                        + q_ab * a * b
                        + constant
                        + instance,
                )
            },
        );

        StandardPlonkConfig {
            a,
            b,
            c,
            q_a,
            q_b,
            q_c,
            q_ab,
            constant,
            instance,
        }
    }
}

#[derive(Clone, Default)]
pub struct StandardPlonk(Fr);

impl StandardPlonk {
    pub fn rand<R: RngCore>(mut rng: R) -> Self {
        Self(Fr::from(rng.next_u32() as u64))
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![vec![self.0]]
    }

    pub fn gen_pk(&self, params: &ParamsKZG<Bn256>) -> ProvingKey<G1Affine> {
        let vk = keygen_vk(params, self).unwrap();
        keygen_pk(params, vk, self).unwrap()
    }

    pub fn gen_proof(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        instances: Vec<Vec<Fr>>,
    ) -> Vec<u8> {
        let instances = instances
            .iter()
            .map(|instances| instances.as_slice())
            .collect_vec();
        let proof = {
            let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverGWC<_>,
                _,
                _,
                EvmTranscript<_, _, _, _>,
                _,
            >(
                params,
                pk,
                &[self],
                &[instances.as_slice()],
                OsRng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        };

        proof
    }
}

impl Circuit<Fr> for StandardPlonk {
    type Config = StandardPlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        meta.set_minimum_degree(4);
        StandardPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "",
            |mut region| {
                region.assign_advice(|| "", config.a, 0, || Value::known(self.0))?;
                region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::ONE))?;

                region.assign_advice(|| "", config.a, 1, || Value::known(-Fr::from(5)))?;
                for (idx, column) in (1..).zip([
                    config.q_a,
                    config.q_b,
                    config.q_c,
                    config.q_ab,
                    config.constant,
                ]) {
                    region.assign_fixed(|| "", column, 1, || Value::known(Fr::from(idx)))?;
                }

                let a = region.assign_advice(|| "", config.a, 2, || Value::known(Fr::ONE))?;
                a.copy_advice(|| "", &mut region, config.b, 3)?;
                a.copy_advice(|| "", &mut region, config.c, 4)?;

                Ok(())
            },
        )
    }
}

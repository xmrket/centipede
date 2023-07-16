#![allow(non_snake_case)]

#[macro_use]
extern crate criterion;

extern crate centipede;
extern crate curv;

mod bench {

    use centipede::juggling::proof_system::Proof;
    use centipede::juggling::segmentation::Msegmentation;
    use criterion::Criterion;

    use curv::elliptic::curves::{Curve, Ed25519, Point, Scalar};

    pub struct SecretShare<E: Curve> {
        pub secret: Scalar<E>,
        pub pubkey: Point<E>,
    }

    impl<E: Curve> SecretShare<E> {
        pub fn generate() -> SecretShare<E> {
            let base_point = Point::<E>::generator();
            let secret: Scalar<E> = Scalar::<E>::random();

            let pubkey = base_point * &secret;
            SecretShare { secret, pubkey }
        }
    }

    pub fn full_backup_cycle(c: &mut Criterion) {
        c.bench_function("full_backup_cycle", move |b| {
            let segment_size = 8;
            let y: Scalar<Ed25519> = Scalar::<Ed25519>::random();
            let G = Point::<Ed25519>::generator();
            let Y = G.clone() * &y;
            let x = SecretShare::generate();
            let Q = G.clone() * &x.secret;
            b.iter(|| {
                let (segments, encryptions) =
                    Msegmentation::to_encrypted_segments(&x.secret, &segment_size, 32, &Y, &G);
                let proof = Proof::prove(&segments, &encryptions, &G, &Y, &segment_size);
                let _secret_decrypted = Msegmentation::decrypt(&encryptions, &G, &y, &segment_size);
                let result = proof.verify(&encryptions, &G, &Y, &Q, &segment_size);
                assert!(result.is_ok());
            })
        });
    }

    pub fn create_backup(c: &mut Criterion) {
        c.bench_function("create_backup", move |b| {
            let segment_size = 8;
            let y: Scalar<Ed25519> = Scalar::<Ed25519>::random();
            let G = Point::<Ed25519>::generator();
            let Y = G.clone() * &y;
            let x = SecretShare::generate();

            b.iter(|| {
                let (segments, encryptions) =
                    Msegmentation::to_encrypted_segments(&x.secret, &segment_size, 32, &Y, &G);
                let _proof = Proof::prove(&segments, &encryptions, &G, &Y, &segment_size);
            })
        });
    }

    pub fn recover_backup(c: &mut Criterion) {
        c.bench_function("recover_backup", move |b| {
            let segment_size = 8;
            let y: Scalar<Ed25519> = Scalar::<Ed25519>::random();
            let G = Point::<Ed25519>::generator();
            let Y = G.clone() * &y;
            let x = SecretShare::generate();
            let Q = G.clone() * &x.secret;

            let (segments, encryptions) =
                Msegmentation::to_encrypted_segments(&x.secret, &segment_size, 32, &Y, &G);
            let proof = Proof::prove(&segments, &encryptions, &G, &Y, &segment_size);
            b.iter(|| {
                let _secret_decrypted = Msegmentation::decrypt(&encryptions, &G, &y, &segment_size);
                let result = proof.verify(&encryptions, &G, &Y, &Q, &segment_size);
                assert!(result.is_ok());
            })
        });
    }

    criterion_group! {
    name = v_backup;
    config = Criterion::default().sample_size(2);
    targets =full_backup_cycle,
    create_backup,
    recover_backup
    }
}
//fn main() {}
criterion_main!(bench::v_backup);

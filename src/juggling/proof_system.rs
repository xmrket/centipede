#![allow(non_snake_case)]
/*
centipede

Copyright 2018 by Kzen Networks

This file is part of centipede library
(https://github.com/KZen-networks/centipede)

Escrow-recovery is free software: you can redistribute
it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

@license GPL-3.0+ <https://github.com/KZen-networks/centipede/blob/master/LICENSE>
*/
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_encryption_of_dlog::{HomoELGamalDlogProof,HomoElGamalDlogWitness,HomoElGamalDlogStatement};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::{HomoELGamalProof,HomoElGamalWitness,HomoElGamalStatement};
use curv::arithmetic::traits::Converter;
use bulletproof::proofs::range_proof::{RangeProof,generate_random_point};
use juggling::segmentation::Msegmentation;
use Errors::{self, ErrorProving};
use serde::{Deserialize, Serialize};

use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Curve, Point, Scalar};
use sha2::{Sha256, Sha512};

#[derive(Serialize, Deserialize)]
pub struct Helgamal<E: Curve> {
    pub D: Point<E>,
    pub E: Point<E>,
}

#[derive(Serialize, Deserialize)]
pub struct Helgamalsegmented<E: Curve> {
    pub DE: Vec<Helgamal<E>>,
}

#[derive(Serialize, Deserialize)]
pub struct Witness<E: Curve> {
    pub x_vec: Vec<Scalar<E>>,
    pub r_vec: Vec<Scalar<E>>,
}

#[derive(Serialize, Deserialize)]
pub struct Proof<E: Curve> {
    pub bulletproof: RangeProof<E>,
    pub elgamal_enc: Vec<HomoELGamalProof<E, Sha256>>,
    pub elgamal_enc_dlog: HomoELGamalDlogProof<E, Sha256>,
}

impl<E: Curve> Proof<E> {
    pub fn prove(
        w: &Witness<E>,
        c: &Helgamalsegmented<E>,
        G: &Point<E>,
        Y: &Point<E>,
        segment_size: &usize,
    ) -> Proof<E> {
        // bulletproofs:
        let num_segments = w.x_vec.len();
        // bit range
        let n = *segment_size;
        // batch size
        let m = num_segments;
        let nm = n * m;
        // some seed for generating g and h vectors
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes_be(KZen);

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<_>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<_>>();

        let range_proof = RangeProof::prove(&g_vec, &h_vec, G, Y, w.x_vec.clone(), &w.r_vec, n);

        // proofs of correct elgamal:

        let elgamal_proofs = (0..num_segments)
            .map(|i| {
                let w = HomoElGamalWitness {
                    r: w.r_vec[i].clone(),
                    x: w.x_vec[i].clone(),
                };
                let delta = HomoElGamalStatement {
                    G: G.clone(),
                    H: G.clone(),
                    Y: Y.clone(),
                    D: c.DE[i].D.clone(),
                    E: c.DE[i].E.clone(),
                };
                HomoELGamalProof::prove(&w, &delta)
            })
            .collect::<Vec<HomoELGamalProof<E, Sha256>>>();

        // proof of correct ElGamal DLog
        let D_vec: Vec<Point<E>> = (0..num_segments).map(|i| c.DE[i].D.clone()).collect();
        let E_vec: Vec<Point<E>> = (0..num_segments).map(|i| c.DE[i].E.clone()).collect();
        let sum_D = Msegmentation::assemble_ge(&D_vec, segment_size);
        let sum_E = Msegmentation::assemble_ge(&E_vec, segment_size);
        let sum_r = Msegmentation::assemble_fe(&w.r_vec, segment_size);
        let sum_x = Msegmentation::assemble_fe(&w.x_vec, segment_size);
        let Q = G.clone() * &sum_x;
        let delta = HomoElGamalDlogStatement {
            G: G.clone(),
            Y: Y.clone(),
            Q,
            D: sum_D,
            E: sum_E,
        };
        let w = HomoElGamalDlogWitness { r: sum_r, x: sum_x };
        let elgamal_dlog_proof = HomoELGamalDlogProof::prove(&w, &delta);

        Proof {
            bulletproof: range_proof,
            elgamal_enc: elgamal_proofs,
            elgamal_enc_dlog: elgamal_dlog_proof,
        }
    }

    pub fn verify(
        &self,
        c: &Helgamalsegmented<E>,
        G: &Point<E>,
        Y: &Point<E>,
        Q: &Point<E>,
        segment_size: &usize,
    ) -> Result<(), Errors> {
        // bulletproofs:
        let num_segments = self.elgamal_enc.len();
        // bit range
        let n = *segment_size;
        // batch size
        let m = num_segments;
        let nm = n * m;
        // some seed for generating g and h vectors
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes_be(KZen);

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<Point<E>>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<Point<E>>>();

        let D_vec: Vec<Point<E>> = (0..num_segments).map(|i| c.DE[i].D.clone()).collect();
        let bp_ver = self
            .bulletproof
            .verify(&g_vec, &h_vec, G, Y, &D_vec, *segment_size)
            .is_ok();

        let elgamal_proofs_ver = (0..num_segments)
            .map(|i| {
                let delta = HomoElGamalStatement {
                    G: G.clone(),
                    H: G.clone(),
                    Y: Y.clone(),
                    D: c.DE[i].D.clone(),
                    E: c.DE[i].E.clone(),
                };
                self.elgamal_enc[i].verify(&delta).is_ok()
            })
            .collect::<Vec<bool>>();

        let E_vec: Vec<Point<E>> = (0..num_segments).map(|i| c.DE[i].E.clone()).collect();
        let sum_D = Msegmentation::assemble_ge(&D_vec, segment_size);
        let sum_E = Msegmentation::assemble_ge(&E_vec, segment_size);

        let delta = HomoElGamalDlogStatement {
            G: G.clone(),
            Y: Y.clone(),
            Q: Q.clone(),
            D: sum_D,
            E: sum_E,
        };

        let elgamal_dlog_proof_ver = self.elgamal_enc_dlog.verify(&delta).is_ok();
        if bp_ver && elgamal_dlog_proof_ver && elgamal_proofs_ver.iter().all(|&x| x) {
            Ok(())
        } else {
            Err(ErrorProving)
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::{ed25519::Ed25519, Point, Scalar};
    use juggling::proof_system::*;
    use juggling::segmentation::Msegmentation;

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

    #[test]
    fn test_varifiable_encryption() {
        let segment_size = 8;
        let y: Scalar<Ed25519> = Scalar::<Ed25519>::random();
        let G = Point::<Ed25519>::generator();
        let Y = G * &y;
        let x = SecretShare::generate();
        let Q = G * &x.secret;
        let (segments, encryptions) =
            Msegmentation::to_encrypted_segments(&x.secret, &segment_size, 32, &Y, &G);
        let secret_new = Msegmentation::assemble_fe(&segments.x_vec, &segment_size);
        let secret_decrypted = Msegmentation::decrypt(&encryptions, &G, &y, &segment_size);

        assert_eq!(x.secret, secret_new);
        assert_eq!(x.secret, secret_decrypted.unwrap());

        let proof = Proof::prove(&segments, &encryptions, &G, &Y, &segment_size);
        let result = proof.verify(&encryptions, &G, &Y, &Q, &segment_size);
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_varifiable_encryption_bad_Q() {
        let segment_size = 8;
        let y: Scalar<Ed25519> = Scalar::<Ed25519>::random();
        let G = Point::<Ed25519>::generator();
        let Y = G * &y;
        let x = SecretShare::generate();
        let Q = G * &x.secret + G;
        let (segments, encryptions) =
            Msegmentation::to_encrypted_segments(&x.secret, &segment_size, 32, &Y, &G);
        let secret_new = Msegmentation::assemble_fe(&segments.x_vec, &segment_size);
        let secret_decrypted = Msegmentation::decrypt(&encryptions, &G, &y, &segment_size);
        assert_eq!(x.secret, secret_new);
        assert_eq!(x.secret, secret_decrypted.unwrap());

        let proof = Proof::prove(&segments, &encryptions, &G, &Y, &segment_size);
        let result = proof.verify(&encryptions, &G, &Y, &Q, &segment_size);
        assert!(result.is_ok());
    }
}

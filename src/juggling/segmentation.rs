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

const SECRETBITS: usize = 256;

use std::marker::PhantomData;
use std::ops::{Shl, Shr};

use curv::arithmetic::traits::*;
use curv::elliptic::curves::{Curve, Point, Scalar};
use curv::BigInt;
use crate::juggling::proof_system::{Helgamal, Helgamalsegmented, Witness};
use rayon::prelude::*;

use crate::Errors::{self, ErrorDecrypting};

pub struct Msegmentation<E: Curve> {
    Curve: PhantomData<*const E>,
}

impl<E: Curve> Msegmentation<E> {
    pub fn get_segment_k(secret: &Scalar<E>, segment_size: &usize, k: u8) -> Scalar<E> {
        let ss_bn = secret.to_bigint();
        let segment_size_u32 = *segment_size as u32;
        let msb = segment_size_u32 * (k as u32 + 1);
        let lsb = segment_size_u32 * k as u32;
        let two_bn = BigInt::from(2);
        let max = BigInt::pow(&two_bn, msb) - BigInt::from(1);
        let min = BigInt::pow(&two_bn, lsb) - BigInt::from(1);
        let mask = max - min;
        let segment_k_bn = mask & ss_bn;
        let segment_k_bn_rotated = BigInt::shr(segment_k_bn, (k * *segment_size as u8) as usize);
        // println!("test = {:?}", test.to_str_radix(16));
        if segment_k_bn_rotated == BigInt::zero() {
            Scalar::<E>::zero()
        } else {
            Scalar::<E>::from(&segment_k_bn_rotated)
        }
    }
    //returns r_k,{D_k,E_k}
    pub fn encrypt_segment_k(
        secret: &Scalar<E>,
        random: &Scalar<E>,
        segment_size: &usize,
        k: u8,
        pub_ke_y: &Point<E>,
        G: &Point<E>,
    ) -> Helgamal<E> {
        let segment_k = Msegmentation::get_segment_k(secret, segment_size, k);
        let E_k = G * random;
        let r_kY = pub_ke_y * random;
        if segment_k == Scalar::<E>::zero() {
            let D_k = r_kY;
            Helgamal { D: D_k, E: E_k }
        } else {
            let x_kG = G * &segment_k;
            let D_k = r_kY + x_kG;
            Helgamal { D: D_k, E: E_k }
        }
    }

    // TODO: find a way using generics to combine the following two fn's
    #[allow(clippy::ptr_arg)] // TODO: resolve this clippy warning (requires major version bump)
    pub fn assemble_fe(segments: &Vec<Scalar<E>>, segment_size: &usize) -> Scalar<E> {
        let two = BigInt::from(2);
        let mut segments_2n = segments.clone();
        let seg1 = segments_2n.remove(0);
        let seg_sum = segments_2n.iter().enumerate().fold(seg1, |acc, (i, s)| {
            if s.clone() == Scalar::<E>::zero() {
                acc
            } else {
                let two_to_the_n = two.pow(*segment_size as u32);
                let two_to_the_n_shifted = two_to_the_n.shl(i * segment_size);
                let two_to_the_n_shifted_fe: Scalar<E> = Scalar::<E>::from(&two_to_the_n_shifted);
                let shifted_segment = s.clone() * two_to_the_n_shifted_fe;
                acc + shifted_segment
            }
        });
        seg_sum
    }

    #[allow(clippy::ptr_arg)] // TODO: resolve this clippy warning (requires major version bump)
    pub fn assemble_ge(segments: &Vec<Point<E>>, segment_size: &usize) -> Point<E> {
        let two = BigInt::from(2);
        let mut segments_2n = segments.clone();
        let seg1 = segments_2n.remove(0);
        let seg_sum = segments_2n.iter().enumerate().fold(seg1, |acc, (i, s)| {
            let two_to_the_n = two.pow(*segment_size as u32);
            let two_to_the_n_shifted = two_to_the_n.shl(i * segment_size);
            let two_to_the_n_shifted_fe: Scalar<E> = Scalar::<E>::from(&two_to_the_n_shifted);
            let shifted_segment = s.clone() * two_to_the_n_shifted_fe;
            acc + shifted_segment
        });
        seg_sum
    }

    pub fn to_encrypted_segments(
        secret: &Scalar<E>,
        segment_size: &usize,
        num_of_segments: usize,
        pub_ke_y: &Point<E>,
        G: &Point<E>,
    ) -> (Witness<E>, Helgamalsegmented<E>) {
        assert_eq!(*segment_size * num_of_segments, SECRETBITS);
        let r_vec = (0..num_of_segments)
            .map(|_| Scalar::<E>::random())
            .collect::<Vec<Scalar<E>>>();
        let segmented_enc = (0..num_of_segments)
            .into_par_iter()
            .map(|i| {
                //  let segment_i = mSegmentation::get_segment_k(secret,segment_size,i as u8);
                Msegmentation::encrypt_segment_k(
                    secret,
                    &r_vec[i],
                    segment_size,
                    i as u8,
                    pub_ke_y,
                    G,
                )
            })
            .collect::<Vec<Helgamal<E>>>();
        let x_vec = (0..num_of_segments)
            .map(|i| Msegmentation::get_segment_k(secret, segment_size, i as u8))
            .collect::<Vec<Scalar<E>>>();
        let w = Witness { x_vec, r_vec };
        let heg_segmented = Helgamalsegmented { DE: segmented_enc };
        (w, heg_segmented)
    }

    //TODO: implement a more advance algorithm for dlog
    pub fn decrypt_segment(
        DE: &Helgamal<E>,
        G: &Point<E>,
        private_key: &Scalar<E>,
        limit: &u32,
        table: &[Point<E>],
    ) -> Result<Scalar<E>, Errors> {
        let mut result = None;

        let limit_plus_one = *limit + 1u32;
        let out_of_limit_fe: Scalar<E> = Scalar::<E>::from(&BigInt::from(limit_plus_one));
        let out_of_limit_ge: Point<E> = G.clone() * &out_of_limit_fe;
        let yE = DE.E.clone() * private_key;
        // handling 0 segment
        let mut D_minus_yE: Point<E> = out_of_limit_ge;
        if yE == DE.D.clone() {
            result = Some(());
        } else {
            D_minus_yE = &DE.D - &yE;
        }
        // TODO: make bound bigger then 32
        let mut table_iter = table.iter().enumerate();
        // find is short-circuiting //TODO: counter measure against side channel attacks
        let matched_value_index = table_iter.find(|&x| x.1 == &D_minus_yE);
        match matched_value_index {
            Some(x) => Ok(Scalar::<E>::from(&BigInt::from(x.0 as u32 + 1))),
            None => {
                if result.is_some() {
                    Ok(Scalar::<E>::zero())
                } else {
                    Err(ErrorDecrypting)
                }
            }
        }
    }

    pub fn decrypt(
        DE_vec: &Helgamalsegmented<E>,
        G: &Point<E>,
        private_key: &Scalar<E>,
        segment_size: &usize,
    ) -> Result<Scalar<E>, Errors> {
        let limit = 2u32.pow(*segment_size as u32);
        let test_ge_table = (1..limit)
            .into_par_iter()
            .map(|i| {
                let test_fe = Scalar::<E>::from(&BigInt::from(i));
                G * &test_fe
            })
            .collect::<Vec<Point<E>>>();
        let vec_secret = (0..DE_vec.DE.len())
            .into_par_iter()
            .map(|i| {
                //   .expect("error decrypting");
                Msegmentation::decrypt_segment(
                    &DE_vec.DE[i],
                    G,
                    private_key,
                    &limit,
                    &test_ge_table,
                )
            })
            .collect::<Vec<Result<Scalar<E>, Errors>>>();
        let mut flag = true;
        let vec_secret_unwrap = (0..vec_secret.len())
            .into_iter()
            .map(|i| {
                if vec_secret[i].is_err() {
                    flag = false;
                    Scalar::<E>::zero()
                } else {
                    vec_secret[i].as_ref().unwrap().clone()
                }
            })
            .collect::<Vec<Scalar<E>>>();
        match flag {
            false => Err(ErrorDecrypting),
            true => Ok(Msegmentation::assemble_fe(&vec_secret_unwrap, segment_size)),
        }
    }
}

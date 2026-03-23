use crate::params::*;
use nalgebra::{DMatrix, SMatrix};

pub type Matrix<const ROW: usize, const COL: usize> = SMatrix<u16, ROW, COL>;
pub type MatNByNbar = Matrix<PARAMS_N, PARAMS_NBAR>;
pub type MatNbar = Matrix<PARAMS_NBAR, PARAMS_NBAR>;
pub type MatNbarByN = Matrix<PARAMS_NBAR, PARAMS_N>;
pub type MatA = DMatrix<u16>;

pub type PublicKey = [u8; CRYPTO_PUBLICKEYBYTES];
pub type SecretKey = [u8; CRYPTO_SECRETKEYBYTES];
pub type Ciphertext = [u8; CRYPTO_CIPHERTEXTBYTES];
pub type SharedSecret = [u8; CRYPTO_BYTES];

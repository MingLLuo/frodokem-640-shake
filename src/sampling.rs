use crate::{crypto::*, params::*, types::*};

// Samples one error value using Frodo's CDF method.
pub fn sample(r: u16, table: &[u16]) -> u16 {
    let t = r >> 1;
    let sign = r & 1;
    let mut e: i16 = 0;

    for &z in table.iter().take(table.len() - 1) {
        e += ((z.wrapping_sub(t)) >> 15) as i16;
    }
    (if sign == 0 { e } else { -e }) as u16
}

// Samples a ROW x COL matrix from a slice of 16-bit pseudo-random values.
pub fn sample_matrix<const ROW: usize, const COL: usize>(
    rnd: &[u16],
) -> Result<Matrix<ROW, COL>, String> {
    if rnd.len() != (ROW * COL) {
        return Err("invalid random input length".to_string());
    }

    let mut out = Matrix::<ROW, COL>::zeros();
    for (idx, &word) in rnd.iter().enumerate() {
        let row = idx / COL;
        let col = idx % COL;
        out[(row, col)] = sample(word, &CDF_TABLE);
    }
    Ok(out)
}

pub fn le_bytes_to_u16_words(bytes: &[u8]) -> Vec<u16> {
    let mut out = vec![0u16; bytes.len() / 2];
    for i in 0..out.len() {
        out[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    }
    out
}

fn expand_seed_to_words(prefix: u8, seed_se: &[u8], words_len: usize) -> Result<Vec<u16>, String> {
    if seed_se.len() != BYTES_SEED_SE {
        return Err("seed len".to_string());
    }

    let mut input = [0u8; 1 + BYTES_SEED_SE];
    input[0] = prefix;
    input[1..].copy_from_slice(seed_se);
    let mut bytes = vec![0u8; 2 * words_len];
    shake128_expand_into(&input, &mut bytes);
    Ok(le_bytes_to_u16_words(&bytes))
}

pub fn sample_keygen_matrices(seed_se: &[u8]) -> Result<(MatNbarByN, MatNByNbar), String> {
    // r = SHAKE(0x5F || seedSE, 32 * n * nHat) -> 2*n*nHat words.
    let words = expand_seed_to_words(0x5f, seed_se, 2 * PARAMS_N * PARAMS_NBAR)?;
    let split = PARAMS_N * PARAMS_NBAR;
    let st: MatNbarByN = sample_matrix(&words[..split])?;
    let e: MatNByNbar = sample_matrix(&words[split..])?;
    Ok((st, e))
}

pub fn sample_ephemeral_matrices(
    seed_se: &[u8],
) -> Result<(MatNbarByN, MatNbarByN, MatNbar), String> {
    // r = SHAKE(0x96 || seedSE, 16 * (2 * nHat * n + nHat^2))
    let r_words_len = 2 * PARAMS_NBAR * PARAMS_N + PARAMS_NBAR * PARAMS_NBAR;
    let r = expand_seed_to_words(0x96, seed_se, r_words_len)?;

    // S', E', E"
    let split_sp = PARAMS_NBAR * PARAMS_N;
    let split_ep = 2 * split_sp;
    let s_prime: MatNbarByN = sample_matrix(&r[..split_sp])?;
    let e_prime: MatNbarByN = sample_matrix(&r[split_sp..split_ep])?;
    let e2: MatNbar = sample_matrix(&r[split_ep..])?;
    Ok((s_prime, e_prime, e2))
}

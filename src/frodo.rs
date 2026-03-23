use crate::{crypto::*, matrix::*, params::*, sampling::*, types::*};

// Encode mu (B*nbar*nbar bits) into an nbar*nbar matrix in Z_q
pub fn encode(mu: &[u8; BYTES_MU]) -> MatNbar {
    let mut out = MatNbar::zeros();

    for i in 0..PARAMS_NBAR {
        for j in 0..PARAMS_NBAR {
            let mut val = 0u16;
            for k in 0..PARAMS_EXTRACTED_BITS {
                let bit_pos = (i * PARAMS_NBAR + j) * PARAMS_EXTRACTED_BITS + k;
                let bit = (mu[bit_pos / 8] >> (bit_pos % 8)) & 1;
                val |= (bit as u16) << k;
            }
            // val * q / 2^B = val * 2^(logQ - B)
            out[(i, j)] = val << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS);
        }
    }
    out
}

// Decode an nbar*nbar matrix from Z_q back to mu
pub fn decode(m: &MatNbar) -> [u8; BYTES_MU] {
    let mut mu = [0u8; BYTES_MU];
    let q_mask = PARAMS_Q - 1;
    let b_mask = (1u16 << PARAMS_EXTRACTED_BITS) - 1;
    let rounding = 1u16 << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS - 1);

    for i in 0..PARAMS_NBAR {
        for j in 0..PARAMS_NBAR {
            // c = round(C[i,j] * 2^B / q) mod 2^B
            let c =
                ((m[(i, j)] & q_mask) + rounding) >> (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS) & b_mask;
            for k in 0..PARAMS_EXTRACTED_BITS {
                let bit_pos = (i * PARAMS_NBAR + j) * PARAMS_EXTRACTED_BITS + k;
                let bit = ((c >> k) & 1) as u8;
                mu[bit_pos / 8] |= bit << (bit_pos % 8);
            }
        }
    }

    mu
}

// Pack a matrix into a bitstream with d bits per entry (row-major)
pub fn pack<const ROW: usize, const COL: usize>(
    input: &Matrix<ROW, COL>,
    d: usize,
) -> Result<Vec<u8>, String> {
    if d == 0 || d > 16 {
        return Err("invalid bit width".to_string());
    }

    let mut out = vec![0u8; (ROW * COL * d).div_ceil(8)];
    let mask = (1 << d) - 1;

    // b[(i * n2 + j)D + k] = c[D-1-k]
    for i in 0..ROW {
        for j in 0..COL {
            let c_ij = input[(i, j)] & mask as u16;
            for k in 0..d {
                let bit = (c_ij >> (d - 1 - k)) & 1;
                let bit_pos = (i * COL + j) * d + k;
                let idx = (bit_pos / 8, 7 - (bit_pos % 8));
                out[idx.0] |= (bit as u8) << idx.1;
            }
        }
    }

    Ok(out)
}

// Unpack a bitstream into a matrix with d bits per entry (row-major)
pub fn unpack<const ROW: usize, const COL: usize>(
    input: &[u8],
    d: usize,
) -> Result<Matrix<ROW, COL>, String> {
    if d == 0 || d > 16 {
        return Err("invalid bit width".to_string());
    }

    if input.len() != (ROW * COL * d).div_ceil(8) {
        return Err("invalid packed input length".to_string());
    }

    let mut out = Matrix::<ROW, COL>::zeros();

    // C[i,j] = sum_{k=0..D-1} b[(i*n2+j)D+k] * 2^(D-1-k)
    for i in 0..ROW {
        for j in 0..COL {
            let mut c_ij = 0u16;
            for k in 0..d {
                let bit_pos = (i * COL + j) * d + k;
                let idx = (bit_pos / 8, 7 - (bit_pos % 8));
                let bit = ((input[idx.0] >> idx.1) & 1) as u16;
                c_ij |= bit << (d - 1 - k);
            }
            out[(i, j)] = c_ij;
        }
    }

    Ok(out)
}

fn split_ciphertext(ct: &Ciphertext) -> (&[u8], &[u8], &[u8]) {
    let (c1, tail) = ct.split_at(BYTES_CT_C1);
    let (c2, salt) = tail.split_at(BYTES_CT_C2);
    (c1, c2, salt)
}

fn split_secret_key(sk: &SecretKey) -> (&[u8], &[u8], &[u8], &[u8], &[u8]) {
    let (s_seed, tail) = sk.split_at(CRYPTO_BYTES);
    let (pk, tail) = tail.split_at(CRYPTO_PUBLICKEYBYTES);
    let (st_bytes, pkh) = tail.split_at(2 * PARAMS_N * PARAMS_NBAR);
    let (seed_a, b_bytes) = pk.split_at(BYTES_SEED_A);
    (s_seed, seed_a, b_bytes, st_bytes, pkh)
}

fn derive_seed_se_and_key(
    pkh: &[u8],
    mu: &[u8],
    salt: &[u8],
) -> ([u8; BYTES_SEED_SE], [u8; CRYPTO_BYTES]) {
    let mut out = [0u8; BYTES_SEED_SE + CRYPTO_BYTES];
    shake128_expand_parts_into(&[pkh, mu, salt], &mut out);
    let (seed_se_bytes, key_bytes) = out.split_at(BYTES_SEED_SE);
    let mut seed_se = [0u8; BYTES_SEED_SE];
    let mut key = [0u8; CRYPTO_BYTES];
    seed_se.copy_from_slice(seed_se_bytes);
    key.copy_from_slice(key_bytes);
    (seed_se, key)
}

fn derive_shared_secret(c1: &[u8], c2: &[u8], salt: &[u8], key: &[u8]) -> SharedSecret {
    let mut ss = [0u8; CRYPTO_BYTES];
    shake128_expand_parts_into(&[c1, c2, salt, key], &mut ss);
    ss
}

// Matrix A generation with SHAKE128
pub fn generate_a_shake128(seed_a: &[u8]) -> MatA {
    let mut a = MatA::zeros(PARAMS_N, PARAMS_N);
    let q_mask = PARAMS_Q - 1; // q = 2^15
    let mut input = [0u8; 2 + BYTES_SEED_A];
    let mut row_stream = [0u8; 2 * PARAMS_N];
    input[2..].copy_from_slice(seed_a);

    for i in 0..PARAMS_N {
        // input <- <i> || seedA
        input[..2].copy_from_slice(&(i as u16).to_le_bytes());

        // 16*n bits -> 2*n bytes
        shake128_expand_into(&input, &mut row_stream);
        for j in 0..PARAMS_N {
            // A[i,j] = c[i,j] mod q
            let cij = u16::from_le_bytes([row_stream[2 * j], row_stream[2 * j + 1]]);
            a[(i, j)] = cij & q_mask;
        }
    }

    a
}

pub fn keygen() -> Result<(PublicKey, SecretKey), String> {
    // random sample in the beginning
    let mut materials = [0u8; CRYPTO_BYTES + BYTES_SEED_SE + BYTES_Z];
    random_fill(&mut materials);
    let (s_seed, rest) = materials.split_at(CRYPTO_BYTES);
    let (seed_se, z) = rest.split_at(BYTES_SEED_SE);

    // seedA = SHAKE(z, lenA)
    let mut seed_a = [0u8; BYTES_SEED_A];
    shake128_expand_into(z, &mut seed_a);

    // A = Gen(seedA)
    let a = generate_a_shake128(&seed_a);

    // S^T / E from SHAKE(0x5F || seedSE, ...)
    let (st, e) = sample_keygen_matrices(seed_se)?;

    // B = A * S + E, where S = (S^T)^T
    let b = mat_a_mul_st_plus_e(&a, &st, &e);

    // b = Pack(B), pk = seedA || b
    let packed_b = pack(&b, PARAMS_LOGQ)?;
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let (pk_seed, pk_b) = pk.split_at_mut(BYTES_SEED_A);
    pk_seed.copy_from_slice(&seed_a);
    pk_b.copy_from_slice(&packed_b);

    // pkh = SHAKE(seedA || b, lensec)
    let mut pkh = [0u8; CRYPTO_BYTES];
    shake128_expand_into(&pk, &mut pkh);

    // sk = s || seedA || b || S^T || pkh
    // => s || pk || S^T || pkh because pk = seedA || b
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let (sk_s, rest) = sk.split_at_mut(CRYPTO_BYTES);
    let (sk_pk, rest) = rest.split_at_mut(CRYPTO_PUBLICKEYBYTES);
    let (sk_st, sk_pkh) = rest.split_at_mut(2 * PARAMS_N * PARAMS_NBAR);

    sk_s.copy_from_slice(s_seed);
    sk_pk.copy_from_slice(&pk);

    // Encode S^T
    for i in 0..PARAMS_NBAR {
        for j in 0..PARAMS_N {
            let off = 2 * (i * PARAMS_N + j);
            sk_st[off..off + 2].copy_from_slice(&st[(i, j)].to_le_bytes());
        }
    }
    sk_pkh.copy_from_slice(&pkh);

    Ok((pk, sk))
}

pub fn encaps(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), String> {
    let mut u = [0u8; CRYPTO_BYTES];
    let mut salt = [0u8; BYTES_SALT];
    random_fill(&mut u);
    random_fill(&mut salt);

    // pkh = SHAKE(pk, lensec)
    let mut pkh = [0u8; CRYPTO_BYTES];
    shake128_expand_into(pk, &mut pkh);

    // seedSE || k = SHAKE(pkh || u || salt, lenSE + lensec)
    let (seed_se, k) = derive_seed_se_and_key(&pkh, &u, &salt);

    // Sample S' / E' / error matrix E''
    let (s_prime, e_prime, e_double_prime) = sample_ephemeral_matrices(&seed_se)?;

    // Parse pk = seedA || b.
    let (seed_a_bytes, b_bytes) = pk.split_at(BYTES_SEED_A);

    // A = Gen(seedA), B' = S' * A + E', c1 = Pack(B')
    let a = generate_a_shake128(seed_a_bytes);
    let b_prime = mat_s_mul_a_plus_e(&s_prime, &a, &e_prime);
    let c1 = pack(&b_prime, PARAMS_LOGQ)?;

    // B = Unpack(b), V = S' * B + E"
    let b = unpack::<PARAMS_N, PARAMS_NBAR>(b_bytes, PARAMS_LOGQ)?;
    let v = mat_s_mul_b_plus_e2(&s_prime, &b, &e_double_prime);

    // C = V + Encode(u), c2 = Pack(C)
    let mut mu = [0u8; BYTES_MU];
    mu.copy_from_slice(&u[..BYTES_MU]);
    let enc_u = encode(&mu);
    let c_mat = mat_add(&v, &enc_u);
    let c2 = pack(&c_mat, PARAMS_LOGQ)?;

    // ss = SHAKE(c1 || c2 || salt || k, lensec)
    let ss = derive_shared_secret(&c1, &c2, &salt, &k);

    // ct = c1 || c2 || salt
    let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let (ct_c1, rest) = ct.split_at_mut(BYTES_CT_C1);
    let (ct_c2, ct_salt) = rest.split_at_mut(BYTES_CT_C2);
    ct_c1.copy_from_slice(&c1);
    ct_c2.copy_from_slice(&c2);
    ct_salt.copy_from_slice(&salt);

    Ok((ct, ss))
}

pub fn decaps(sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, String> {
    // Parse ciphertext c = c1 || c2 || salt.
    let (ct_c1, ct_c2, ct_salt) = split_ciphertext(ct);

    // Parse secret key sk = s || pk(seedA||b) || S^T || pkh.
    let (sk_s_seed, sk_seed_a, sk_b_bytes, sk_st_bytes, sk_pkh) = split_secret_key(sk);
    // Parse S^T
    let st = MatNbarByN::from_fn(|i, j| {
        // 2 * u8 -> u16
        let off = 2 * (i * PARAMS_N + j);
        u16::from_le_bytes([sk_st_bytes[off], sk_st_bytes[off + 1]])
    });

    // B' = Unpack(c1, nHat, n), C = Unpack(c2, nHat, nHat).
    let b_prime = unpack::<PARAMS_NBAR, PARAMS_N>(ct_c1, PARAMS_LOGQ)?;
    let c = unpack::<PARAMS_NBAR, PARAMS_NBAR>(ct_c2, PARAMS_LOGQ)?;

    // M = C - B' * S, u' = Decode(M), S = (S^T)^T.
    let bs = mat_b_prime_mul_st(&b_prime, &st);
    let m = mat_sub(&c, &bs);
    let u_prime = decode(&m);

    // seedSE' || k' = SHAKE(pkh || u' || salt, lenSE + lensec)
    let (seed_se_prime, k_prime) = derive_seed_se_and_key(sk_pkh, &u_prime, ct_salt);

    // Re-generate S', E', E" from pseudorandom bit string
    let (s_prime, e_prime, e_double_prime) = sample_ephemeral_matrices(&seed_se_prime)?;

    // B" = S' * A + E'.
    let a = generate_a_shake128(sk_seed_a);
    let b_double = mat_s_mul_a_plus_e(&s_prime, &a, &e_prime);

    // B = Unpack(b, n, nHat), V = S' * B + E", C' = V + Encode(u').
    let b = unpack::<PARAMS_N, PARAMS_NBAR>(sk_b_bytes, PARAMS_LOGQ)?;
    let v = mat_s_mul_b_plus_e2(&s_prime, &b, &e_double_prime);
    let enc_u_prime = encode(&u_prime);
    let c_prime = mat_add(&v, &enc_u_prime);

    // kHat = k' if B' == B" and C == C', otherwise s.
    let q_mask = PARAMS_Q - 1;
    let ok_b = ct_eq_matrix_masked(&b_prime, &b_double, q_mask);
    let ok_c = ct_eq_matrix_masked(&c, &c_prime, q_mask);
    let mask = 0u8.wrapping_sub(ok_b & ok_c);

    let mut k_hat = [0u8; CRYPTO_BYTES];
    for i in 0..CRYPTO_BYTES {
        k_hat[i] = (k_prime[i] & mask) | (sk_s_seed[i] & !mask);
    }

    // ss = SHAKE(c1 || c2 || salt || kHat, lensec)
    Ok(derive_shared_secret(ct_c1, ct_c2, ct_salt, &k_hat))
}

// This test is generated by CodeX
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        path::PathBuf,
        thread,
        time::Instant,
    };

    const KAT_FILE: &str = "PQCkemKAT_19888_shake.rsp";
    const KAT_CASES: usize = 100;

    struct KatCase {
        count: usize,
        sk: SecretKey,
        ct: Ciphertext,
        ss: SharedSecret,
    }

    fn kat_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("kat")
            .join(KAT_FILE)
    }

    fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), 2 * N, "hex length mismatch");
        let mut out = [0u8; N];
        for i in 0..N {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("invalid hex byte in KAT");
        }
        out
    }

    fn read_kat_cases() -> Vec<KatCase> {
        let path = kat_path();
        let f = File::open(&path)
            .expect("missing KAT file: put it under kat/PQCkemKAT_19888_shake.rsp");
        let reader = BufReader::new(f);

        let mut out = Vec::with_capacity(KAT_CASES);
        let mut count = None;
        let mut sk = None;
        let mut ct = None;

        for line in reader.lines() {
            let line = line.expect("failed to read KAT line");
            if let Some(v) = line.strip_prefix("count = ") {
                count = Some(v.parse::<usize>().expect("invalid KAT count"));
            } else if let Some(v) = line.strip_prefix("sk = ") {
                sk = Some(hex_to_array::<CRYPTO_SECRETKEYBYTES>(v));
            } else if let Some(v) = line.strip_prefix("ct = ") {
                ct = Some(hex_to_array::<CRYPTO_CIPHERTEXTBYTES>(v));
            } else if let Some(v) = line.strip_prefix("ss = ") {
                out.push(KatCase {
                    count: count.expect("missing count in KAT case"),
                    sk: sk.take().expect("missing sk in KAT case"),
                    ct: ct.take().expect("missing ct in KAT case"),
                    ss: hex_to_array::<CRYPTO_BYTES>(v),
                });
            }
        }

        assert_eq!(out.len(), KAT_CASES, "unexpected number of KAT cases");
        out
    }

    #[test]
    fn decaps_matches_official_kat() {
        let cases = read_kat_cases();
        let threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(cases.len().max(1));
        let chunk = cases.len().div_ceil(threads).max(1);
        let start = Instant::now();

        thread::scope(|scope| {
            for block in cases.chunks(chunk) {
                scope.spawn(move || {
                    for case in block {
                        let ss = decaps(&case.sk, &case.ct).expect("decaps should succeed");
                        assert_eq!(ss, case.ss, "KAT mismatch at count {}", case.count);
                    }
                });
            }
        });

        let elapsed = start.elapsed();
        let ops = cases.len() as f64 / elapsed.as_secs_f64();
        let ms_per_case = elapsed.as_secs_f64() * 1000.0 / cases.len() as f64;
        eprintln!(
            "KAT decaps: {} cases on {} threads in {:.3}s ({:.2} ops/s, {:.3} ms/case)",
            cases.len(),
            threads,
            elapsed.as_secs_f64(),
            ops,
            ms_per_case
        );
    }
}

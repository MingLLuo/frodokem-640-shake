// FrodoKEM-640 (SHAKE) parameters.
pub const PARAMS_N: usize = 640;
pub const PARAMS_NBAR: usize = 8;
pub const PARAMS_LOGQ: usize = 15;
pub const PARAMS_Q: u16 = 1 << PARAMS_LOGQ;
// Denoted by 'B' in spec.
pub const PARAMS_EXTRACTED_BITS: usize = 2;

// 128-bit seeds/keys.
pub const BYTES_SEED_A: usize = 16;
pub const BYTES_Z: usize = 16;
pub const CRYPTO_BYTES: usize = 16; // Shared secret size.
pub const BYTES_SEED_SE: usize = 2 * CRYPTO_BYTES;
pub const BYTES_SALT: usize = 2 * CRYPTO_BYTES;
pub const BYTES_MU: usize = (PARAMS_EXTRACTED_BITS * PARAMS_NBAR * PARAMS_NBAR) / 8;

// Packed matrix sizes (15 bits per entry).
pub const BYTES_PK_B: usize = (PARAMS_LOGQ * PARAMS_N * PARAMS_NBAR) / 8; // B in pk
pub const BYTES_CT_C1: usize = BYTES_PK_B; // B' in ct
pub const BYTES_CT_C2: usize = (PARAMS_LOGQ * PARAMS_NBAR * PARAMS_NBAR) / 8; // C in ct

// API object sizes for Frodo640.
pub const CRYPTO_PUBLICKEYBYTES: usize = BYTES_SEED_A + BYTES_PK_B; // 9616
pub const CRYPTO_CIPHERTEXTBYTES: usize = BYTES_CT_C1 + BYTES_CT_C2 + BYTES_SALT; // 9752
pub const CRYPTO_SECRETKEYBYTES: usize =
    CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + (2 * PARAMS_N * PARAMS_NBAR) + CRYPTO_BYTES; // 19888

// Frodo640 error-distribution CDF
// https://datatracker.ietf.org/doc/html/draft-longa-cfrg-frodokem-01 Table 5
pub const CDF_TABLE_LEN: usize = 13;
pub const CDF_TABLE: [u16; CDF_TABLE_LEN] = [
    4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
];

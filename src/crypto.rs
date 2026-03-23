use rand::{RngCore, rngs::OsRng};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update},
};

pub fn shake128_expand_into(input: &[u8], out: &mut [u8]) {
    let mut h = Shake128::default();
    h.update(input);
    h.finalize_xof_into(out);
}

pub fn shake128_expand_parts_into(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake128::default();
    for part in parts {
        h.update(part);
    }
    h.finalize_xof_into(out);
}

pub fn random_fill(out: &mut [u8]) {
    let mut rng = OsRng;
    rng.fill_bytes(out);
}

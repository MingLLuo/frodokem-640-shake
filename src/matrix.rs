use crate::{params::*, types::*};

fn mat_mul_add_kernel<const ROW: usize, const INNER: usize, const COL: usize>(
    mut add: impl FnMut(usize, usize) -> u16,
    mut lhs: impl FnMut(usize, usize) -> u16,
    mut rhs: impl FnMut(usize, usize) -> u16,
) -> Matrix<ROW, COL> {
    let mut out = Matrix::<ROW, COL>::zeros();
    for r in 0..ROW {
        for c in 0..COL {
            let mut sum = add(r, c);
            for j in 0..INNER {
                sum = sum.wrapping_add(lhs(r, j).wrapping_mul(rhs(j, c)));
            }
            out[(r, c)] = sum;
        }
    }
    out
}

pub fn mat_a_mul_st_plus_e(a: &MatA, st: &MatNbarByN, e: &MatNByNbar) -> MatNByNbar {
    mat_mul_add_kernel::<PARAMS_N, PARAMS_N, PARAMS_NBAR>(
        |i, k| e[(i, k)],
        |i, j| a[(i, j)],
        |j, k| st[(k, j)],
    )
}

pub fn mat_s_mul_a_plus_e(s: &MatNbarByN, a: &MatA, e: &MatNbarByN) -> MatNbarByN {
    mat_mul_add_kernel::<PARAMS_NBAR, PARAMS_N, PARAMS_N>(
        |k, i| e[(k, i)],
        |k, j| s[(k, j)],
        |j, i| a[(j, i)],
    )
}

pub fn mat_s_mul_b_plus_e2(s: &MatNbarByN, b: &MatNByNbar, e2: &MatNbar) -> MatNbar {
    mat_mul_add_kernel::<PARAMS_NBAR, PARAMS_N, PARAMS_NBAR>(
        |k, i| e2[(k, i)],
        |k, j| s[(k, j)],
        |j, i| b[(j, i)],
    )
}

pub fn mat_b_prime_mul_st(b_prime: &MatNbarByN, st: &MatNbarByN) -> MatNbar {
    mat_mul_add_kernel::<PARAMS_NBAR, PARAMS_N, PARAMS_NBAR>(
        |_, _| 0u16,
        |i, j| b_prime[(i, j)],
        |j, k| st[(k, j)],
    )
}

pub fn mat_add<const ROW: usize, const COL: usize>(
    lhs: &Matrix<ROW, COL>,
    rhs: &Matrix<ROW, COL>,
) -> Matrix<ROW, COL> {
    Matrix::<ROW, COL>::from_fn(|i, j| lhs[(i, j)].wrapping_add(rhs[(i, j)]))
}

pub fn mat_sub<const ROW: usize, const COL: usize>(
    lhs: &Matrix<ROW, COL>,
    rhs: &Matrix<ROW, COL>,
) -> Matrix<ROW, COL> {
    Matrix::<ROW, COL>::from_fn(|i, j| lhs[(i, j)].wrapping_sub(rhs[(i, j)]))
}

pub fn ct_eq_matrix_masked<const ROW: usize, const COL: usize>(
    lhs: &Matrix<ROW, COL>,
    rhs: &Matrix<ROW, COL>,
    mask: u16,
) -> u8 {
    let mut diff = 0u16;
    for (&x, &y) in lhs.iter().zip(rhs.iter()) {
        diff |= (x & mask) ^ (y & mask);
    }
    let nz = (((diff | diff.wrapping_neg()) >> 15) & 1) as u8;
    1 ^ nz
}

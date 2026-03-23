use std::{env, fs};

mod crypto;
mod frodo;
mod matrix;
mod params;
mod sampling;
mod types;
use crate::frodo::*;
use crate::params::*;

fn usage() {
    eprintln!("Usage:");
    eprintln!("  frodokeygen pkfile skfile");
    eprintln!("  frodoencaps pkfile ctfile ssfile");
    eprintln!("  frododecaps skfile ctfile ssfile");
}

// Template for read N bytes
fn read_fixed<const N: usize>(path: &str) -> Result<[u8; N], String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {}", path, e))?;
    if bytes.len() != N {
        return Err(format!(
            "invalid length for {}: expected {}, got {}",
            path,
            N,
            bytes.len()
        ));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        return Err("Wrong Command".to_string());
    }

    match args[1].as_str() {
        "frodokeygen" => {
            if args.len() < 4 {
                return Err("Not enough Paramaters".to_string());
            }

            let pk_path = &args[2];
            let sk_path = &args[3];

            let (pk, sk) = keygen()?;
            fs::write(sk_path, sk).map_err(|e| format!("failed to write {}: {}", sk_path, e))?;
            fs::write(pk_path, pk).map_err(|e| format!("failed to write {}: {}", pk_path, e))?;
        }
        "frodoencaps" => {
            if args.len() < 5 {
                return Err("Not enough Paramaters".to_string());
            }
            let pkfile = &args[2];
            let ctfile = &args[3];
            let ssfile = &args[4];

            let pk = read_fixed::<CRYPTO_PUBLICKEYBYTES>(pkfile)?;
            let (ct, ss) = encaps(&pk)?;

            fs::write(ctfile, ct).map_err(|e| format!("failed to write {}: {}", ctfile, e))?;
            fs::write(ssfile, ss).map_err(|e| format!("failed to write {}: {}", ssfile, e))?;
        }
        "frododecaps" => {
            if args.len() < 5 {
                return Err("Not enough Paramaters".to_string());
            }
            let skfile = &args[2];
            let ctfile = &args[3];
            let ssfile = &args[4];
            let sk = read_fixed::<CRYPTO_SECRETKEYBYTES>(skfile)?;
            let ct = read_fixed::<CRYPTO_CIPHERTEXTBYTES>(ctfile)?;
            let ss = decaps(&sk, &ct)?;
            fs::write(ssfile, ss).map_err(|e| format!("failed to write {}: {}", ssfile, e))?;
        }
        _ => {
            return Err("Not valid command".to_string());
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        usage();
    }
}

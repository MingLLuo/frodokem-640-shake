# FrodoKEM-640-SHAKE

Based on crate 'naglebra', we implement the FrodoKEM-640-SHAKE scheme. The implementation is based on the reference code provided in the RFC draft for FrodoKEM.

Maybe the design of the code can be better, for generic construction of FrodoKEMs, better code reuse...

## Usage

1. `frodokeygen PUBLICKEYFILE PRIVATEKEYFILE`

- generates a new keypair, storing the public key in PUBLICKEYFILE and the private key in PRIVATEKEYFILE.

2. `frodoencaps PUBLICKEYFILE CIPHERTEXTFILE SHAREDSECRETFILE`

- reads the public key from PUBLICKEYFILE, computes a ciphertext and a shared secret, and stores them in CIPHERTEXTFILE and SHAREDSECRETFILE respectively.

3. `frododecaps PRIVATEKEYFILE CIPHERTEXTFILE SHAREDSECRETFILE`

- reads the private key and ciphertext from PRIVATEKEYFILE and CIPHERTEXTFILE respectively, and writes the shared secret to SHAREDSECRETFILE

The test for 'PQCkemKAT_19888_shake' is also embedded, error messages are printed when the corresponding path for '.rsp' is not found.

## Reference

- [Shorter Proposal for FrodoKEM](https://frodokem.org/files/FrodoKEM_standard_proposal_20250929.pdf)
- [FrodoKEM in Circl](https://github.com/cloudflare/circl/blob/main/kem/frodo/frodo640shake/frodo.go)
- [Internet Draft for FrodoKEM](https://datatracker.ietf.org/doc/html/draft-longa-cfrg-frodokem-01)

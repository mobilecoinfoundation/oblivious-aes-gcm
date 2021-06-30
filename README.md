# MobileCoin: Oblivious AES-GCM

WARNING: You should use RustCrypt [`aes-gcm`](https://github.com/RustCrypto/AEADs) crate, not this one. This crate is a fork of the execellent RustCrypto crate which intentionally removes key safety features of the RustCrypto implementation in order to support a niche use-case for MobileCoin.

This crate is a fork of the RustCrypto crate made in order to introduce a constant-time decrypt-in-place method which can be made part of a larger constant-time execution. This comes at the cost of offloading enforcement of some the "toxic waste cleanup" typically contained with an AES-GCM implementation to the caller (i.e. the larger constant-time execution).

This is necessary when the caller is running inside an trusted execution environment and requires decryption to be completely oblivious. Meaning, when the caller requires branchless, constant-time execution regardless of authentication and decryption success or failure.

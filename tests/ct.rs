//! Tests for MobileCoin's constant-time decryption API.

#![cfg(all(feature = "aes", feature = "alloc", feature = "zeroize"))]

use mc_oblivious_aes_gcm::{
    Aes256Gcm, CtAeadDecrypt,
    aead::{AeadInOut, KeyInit, array::Array},
};

#[test]
fn constant_time_decryption_preserves_the_buffer_on_failure() {
    let key = Array([7; 32]);
    let nonce = Array([9; 12]);
    let cipher = Aes256Gcm::new(&key);
    let associated_data = b"associated data";
    let plaintext = b"MobileCoin plaintext";

    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, associated_data, ciphertext.as_mut_slice().into())
        .unwrap();

    let mut decrypted = ciphertext.clone();
    let result = cipher.ct_decrypt_in_place_detached(&nonce, associated_data, &mut decrypted, &tag);
    assert!(bool::from(result));
    assert_eq!(decrypted, plaintext);

    let mut invalid_tag = tag;
    invalid_tag[0] ^= 1;
    let expected_ciphertext = ciphertext.clone();
    let result =
        cipher.ct_decrypt_in_place_detached(&nonce, associated_data, &mut ciphertext, &invalid_tag);
    assert!(!bool::from(result));
    assert_eq!(ciphertext, expected_ciphertext);
}

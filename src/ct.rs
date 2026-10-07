//! Extra constant-time decryption API.

use crate::{A_MAX, AesGcm, P_MAX, Tag};
use aead::AeadInOut;
use cipher::{
    BlockCipherEncrypt, BlockSizeUser, StreamCipherCore,
    array::{Array, ArraySize},
    consts::U16,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use alloc::vec::Vec;

/// API for Aead in-place decryption which is constant-time with respect to
/// the mac check failing
///
/// This is meant to extend the `AeadInOut` trait and be implemented by those
/// AEAD's which have a constant-time decrypt operation.
pub trait CtAeadDecrypt: AeadInOut {
    /// Decrypt a buffer using given aead nonce, validating associated data
    /// under the mac (tag).
    ///
    /// This API promises to be branchless and constant time, particularly,
    /// not branching on whether or not the mac check succeeded.
    ///
    /// Returns:
    /// Choice::from(true): The mac check succeeded and the buffer contains the
    /// plaintext Choice::from(false): Decryption failed, and the buffer
    /// contains failed decryption.        The caller SHOULD zeroize buffer
    /// before it is discarded.
    fn ct_decrypt_in_place_detached(
        &self,
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Array<u8, Self::TagSize>,
    ) -> CtDecryptResult;
}

/// A new-type wrapper around choice with the #[must_use] annotation that Result
/// has. This wraps the value Choice::from(true) when decryption succeeded, and
/// Choice::from(false) otherwise.
#[must_use = "The result of constant time decryption should not be discarded"]
#[derive(Copy, Clone, Debug)]
pub struct CtDecryptResult(pub Choice);

impl AsRef<Choice> for CtDecryptResult {
    fn as_ref(&self) -> &Choice {
        &self.0
    }
}

impl From<Choice> for CtDecryptResult {
    fn from(src: Choice) -> Self {
        CtDecryptResult(src)
    }
}

impl From<CtDecryptResult> for Choice {
    fn from(src: CtDecryptResult) -> Choice {
        src.0
    }
}

impl From<CtDecryptResult> for bool {
    fn from(src: CtDecryptResult) -> bool {
        bool::from(Choice::from(src))
    }
}

impl<Aes, NonceSize, TagSize> CtAeadDecrypt for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    NonceSize: ArraySize,
    TagSize: crate::TagSize,
{
    /// A constant time version of the original
    /// https://docs.rs/aes-gcm/0.6.0/src/aes_gcm/lib.rs.html#251
    fn ct_decrypt_in_place_detached(
        &self,
        nonce: &Array<u8, NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<TagSize>,
    ) -> CtDecryptResult {
        let len = buffer.len();

        if len as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return CtDecryptResult(Choice::from(0));
        }

        let (ctr, mask) = self.init_ctr(nonce);

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        let expected_tag = self.compute_tag(mask, associated_data, buffer);
        let mut ciphertext = Vec::with_capacity(len);
        ciphertext.extend_from_slice(buffer);
        ctr.apply_keystream_partial(ciphertext.as_mut_slice().into());

        let result = expected_tag[..TagSize::to_usize()].ct_eq(tag.as_slice());

        // Conditionally copy the actual plaintext _only_ if the tag verified
        // correctly, in order to increase misuse resistance and reduce attack
        // surface for chosen ciphertext attacks.
        for i in 0..len {
            buffer[i] = u8::conditional_select(&buffer[i], &ciphertext[i], result);
        }
        // Unconditionally zeroize the decryption result to refrain from keeping
        // a CCA oracle in memory.
        ciphertext.zeroize();

        CtDecryptResult(result)
    }
}

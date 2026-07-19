use alloc::boxed::Box;

use blake2b_simd::Hash as Blake2bHash;

use super::{
    Authorization, TransactionData, TxDigests, TxVersion,
    sighash_v4::{V4SighashDigests, v4_signature_hash, v4_signature_hash_with_precomputed},
    sighash_v5::{Zip244SighashDigests, v5_signature_hash, v5_signature_hash_with_precomputed},
    txid::TxIdDigester,
};
use ::sapling::bundle::GrothProofBytes;

use super::sighash_v6::{v6_signature_hash, v6_signature_hash_with_precomputed};

pub enum SignableInput<'a> {
    Shielded,
    Transparent(transparent::sighash::SignableInput<'a>),
}

impl SignableInput<'_> {
    pub fn hash_type(&self) -> u8 {
        match self {
            SignableInput::Shielded => ::transparent::sighash::SIGHASH_ALL,
            SignableInput::Transparent(input) => input.hash_type().encode(),
        }
    }
}

pub struct SignatureHash(Blake2bHash);

impl AsRef<[u8; 32]> for SignatureHash {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref().try_into().unwrap()
    }
}

#[derive(Clone, Debug)]
enum VersionSpecificSighashDigests {
    PreV5(Box<V4SighashDigests>),
    Zip244(Box<Zip244SighashData>),
}

#[derive(Clone, Debug)]
struct Zip244SighashData {
    txid_parts: TxDigests<Blake2bHash>,
    transparent: Option<Zip244SighashDigests>,
}

/// Transaction-wide digests that can be reused across signature hash calculations.
///
/// The per-input portions of each signature hash, including the hash type and the
/// pre-V5 `scriptCode`, are computed by [`PrecomputedSighashData::signature_hash`].
/// The transaction is owned by this value so its cached digests cannot be combined with another
/// transaction.
#[derive(Debug)]
pub struct PrecomputedSighashData<A: Authorization> {
    tx: TransactionData<A>,
    version_specific: VersionSpecificSighashDigests,
}

impl<
    TA: ::transparent::sighash::TransparentAuthorizingContext,
    SA: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA, TransparentAuth = TA>,
> PrecomputedSighashData<A>
{
    /// Precomputes the transaction-wide digests used by signature hashing.
    pub fn new(tx: TransactionData<A>) -> Self {
        let version_specific = match tx.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                VersionSpecificSighashDigests::PreV5(Box::new(V4SighashDigests::new(&tx)))
            }
            TxVersion::V5 | TxVersion::V6 => {
                let transparent = tx
                    .transparent_bundle
                    .as_ref()
                    .filter(|bundle| !bundle.is_coinbase() && !bundle.vin.is_empty())
                    .map(Zip244SighashDigests::new);
                VersionSpecificSighashDigests::Zip244(Box::new(Zip244SighashData {
                    txid_parts: tx.digest(TxIdDigester),
                    transparent,
                }))
            }
        };

        Self {
            tx,
            version_specific,
        }
    }

    /// Returns the transaction associated with these precomputed digests.
    pub fn transaction(&self) -> &TransactionData<A> {
        &self.tx
    }

    /// Computes a signature hash using the precomputed transaction-wide digests.
    pub fn signature_hash(&self, signable_input: &SignableInput) -> SignatureHash {
        SignatureHash(match (&self.version_specific, self.tx.version) {
            (
                VersionSpecificSighashDigests::PreV5(digests),
                TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4,
            ) => v4_signature_hash_with_precomputed(&self.tx, signable_input, digests),
            (VersionSpecificSighashDigests::Zip244(data), TxVersion::V5) => {
                v5_signature_hash_with_precomputed(
                    &self.tx,
                    signable_input,
                    &data.txid_parts,
                    data.transparent.as_ref(),
                )
            }
            (VersionSpecificSighashDigests::Zip244(data), TxVersion::V6) => {
                v6_signature_hash_with_precomputed(
                    &self.tx,
                    signable_input,
                    &data.txid_parts,
                    data.transparent.as_ref(),
                )
            }
            _ => unreachable!("precomputed digests match their transaction version"),
        })
    }
}

/// Computes the signature hash for an input to a transaction, given
/// the full data of the transaction, the input being signed, and the
/// set of precomputed hashes produced in the construction of the
/// transaction ID.
pub fn signature_hash<
    TA: ::transparent::sighash::TransparentAuthorizingContext,
    SA: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA, TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> SignatureHash {
    SignatureHash(match tx.version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
            v4_signature_hash(tx, signable_input)
        }

        TxVersion::V5 => v5_signature_hash(tx, signable_input, txid_parts),

        TxVersion::V6 => v6_signature_hash(tx, signable_input, txid_parts),
    })
}

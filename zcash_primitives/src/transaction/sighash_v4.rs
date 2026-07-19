use alloc::vec::Vec;
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use ff::PrimeField;

use ::sapling::bundle::{GrothProofBytes, OutputDescription, SpendDescription};
use ::transparent::{
    bundle::{self as transparent, TxIn, TxOut},
    sighash::{SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE},
};
use zcash_protocol::consensus::BranchId;

use super::{
    Authorization, TransactionData,
    components::{sapling as sapling_serialization, sprout::JsDescription},
    sighash::SignableInput,
};

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashSigHash";
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";

macro_rules! update_hash {
    ($h:expr, $cond:expr, $value:expr) => {
        if $cond {
            $h.update(&$value.as_ref());
        } else {
            $h.update(&[0; 32]);
        }
    };
}

fn prevout_hash<TA: transparent::Authorization>(vin: &[TxIn<TA>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vin.len() * 36);
    for t_in in vin {
        t_in.prevout().write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_PREVOUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sequence_hash<TA: transparent::Authorization>(vin: &[TxIn<TA>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vin.len() * 4);
    for t_in in vin {
        data.extend_from_slice(&t_in.sequence().to_le_bytes());
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SEQUENCE_HASH_PERSONALIZATION)
        .hash(&data)
}

fn outputs_hash(vout: &[TxOut]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vout.len() * (4 + 1));
    for t_out in vout {
        t_out.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn single_output_hash(tx_out: &TxOut) -> Blake2bHash {
    let mut data = vec![];
    tx_out.write(&mut data).unwrap();
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn joinsplits_hash(
    consensus_branch_id: BranchId,
    joinsplits: &[JsDescription],
    joinsplit_pubkey: &[u8; 32],
) -> Blake2bHash {
    let mut data = Vec::with_capacity(
        joinsplits.len()
            * if consensus_branch_id.sprout_uses_groth_proofs() {
                1698 // JSDescription with Groth16 proof
            } else {
                1802 // JsDescription with PHGR13 proof
            },
    );
    for js in joinsplits {
        js.write(&mut data).unwrap();
    }
    data.extend_from_slice(joinsplit_pubkey);
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_JOINSPLITS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sapling_spends_hash<
    A: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
>(
    spends: &[SpendDescription<A>],
) -> Blake2bHash {
    let mut data = Vec::with_capacity(spends.len() * 384);
    for s_spend in spends {
        data.extend_from_slice(&s_spend.cv().to_bytes());
        data.extend_from_slice(s_spend.anchor().to_repr().as_ref());
        data.extend_from_slice(s_spend.nullifier().as_ref());
        data.extend_from_slice(&<[u8; 32]>::from(*s_spend.rk()));
        data.extend_from_slice(s_spend.zkproof());
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sapling_outputs_hash(outputs: &[OutputDescription<GrothProofBytes>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(outputs.len() * 948);
    for s_out in outputs {
        sapling_serialization::write_output_v4(&mut data, s_out).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

#[derive(Clone, Debug)]
pub(super) struct V4SighashDigests {
    prevouts: Blake2bHash,
    sequence: Blake2bHash,
    outputs: Blake2bHash,
    joinsplits: Option<Blake2bHash>,
    sapling_spends: Option<Blake2bHash>,
    sapling_outputs: Option<Blake2bHash>,
}

impl V4SighashDigests {
    pub(super) fn new<
        SA: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
        A: Authorization<SaplingAuth = SA>,
    >(
        tx: &TransactionData<A>,
    ) -> Self {
        let transparent_inputs: &[TxIn<A::TransparentAuth>] = tx
            .transparent_bundle
            .as_ref()
            .map_or(&[], |b| b.vin.as_slice());
        let transparent_outputs: &[TxOut] = tx
            .transparent_bundle
            .as_ref()
            .map_or(&[], |b| b.vout.as_slice());

        let joinsplits = tx
            .sprout_bundle
            .as_ref()
            .filter(|bundle| !bundle.joinsplits.is_empty())
            .map(|bundle| {
                joinsplits_hash(
                    tx.consensus_branch_id,
                    &bundle.joinsplits,
                    &bundle.joinsplit_pubkey,
                )
            });

        let sapling_spends = tx
            .sapling_bundle
            .as_ref()
            .filter(|bundle| !bundle.shielded_spends().is_empty())
            .map(|bundle| sapling_spends_hash(bundle.shielded_spends()));
        let sapling_outputs = tx
            .sapling_bundle
            .as_ref()
            .filter(|bundle| !bundle.shielded_outputs().is_empty())
            .map(|bundle| sapling_outputs_hash(bundle.shielded_outputs()));

        Self {
            prevouts: prevout_hash(transparent_inputs),
            sequence: sequence_hash(transparent_inputs),
            outputs: outputs_hash(transparent_outputs),
            joinsplits,
            sapling_spends,
            sapling_outputs,
        }
    }
}

pub fn v4_signature_hash<
    SA: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
) -> Blake2bHash {
    v4_signature_hash_inner(tx, signable_input, None)
}

pub(super) fn v4_signature_hash_with_precomputed<
    SA: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    precomputed: &V4SighashDigests,
) -> Blake2bHash {
    v4_signature_hash_inner(tx, signable_input, Some(precomputed))
}

fn v4_signature_hash_inner<
    SA: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    precomputed: Option<&V4SighashDigests>,
) -> Blake2bHash {
    let hash_type = signable_input.hash_type();
    if tx.version.has_overwinter() {
        let mut personal = [0; 16];
        personal[..12].copy_from_slice(ZCASH_SIGHASH_PERSONALIZATION_PREFIX);
        personal[12..].copy_from_slice(&u32::from(tx.consensus_branch_id).to_le_bytes());

        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(&personal)
            .to_state();

        h.update(&tx.version.header().to_le_bytes());
        h.update(&tx.version.version_group_id().to_le_bytes());
        update_hash!(
            h,
            hash_type & SIGHASH_ANYONECANPAY == 0,
            precomputed.map_or_else(
                || prevout_hash(
                    tx.transparent_bundle
                        .as_ref()
                        .map_or(&[], |b| b.vin.as_slice())
                ),
                |digests| digests.prevouts,
            )
        );
        update_hash!(
            h,
            (hash_type & SIGHASH_ANYONECANPAY) == 0
                && (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE,
            precomputed.map_or_else(
                || sequence_hash(
                    tx.transparent_bundle
                        .as_ref()
                        .map_or(&[], |b| b.vin.as_slice())
                ),
                |digests| digests.sequence,
            )
        );

        if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
            && (hash_type & SIGHASH_MASK) != SIGHASH_NONE
        {
            h.update(
                precomputed
                    .map_or_else(
                        || {
                            outputs_hash(
                                tx.transparent_bundle
                                    .as_ref()
                                    .map_or(&[], |b| b.vout.as_slice()),
                            )
                        },
                        |digests| digests.outputs,
                    )
                    .as_bytes(),
            );
        } else if (hash_type & SIGHASH_MASK) == SIGHASH_SINGLE {
            match (tx.transparent_bundle.as_ref(), signable_input) {
                (Some(b), SignableInput::Transparent(input)) if input.index() < &b.vout.len() => {
                    h.update(single_output_hash(&b.vout[*input.index()]).as_bytes())
                }
                _ => h.update(&[0; 32]),
            };
        } else {
            h.update(&[0; 32]);
        };

        let joinsplits = precomputed.map_or_else(
            || {
                tx.sprout_bundle
                    .as_ref()
                    .filter(|bundle| !bundle.joinsplits.is_empty())
                    .map(|bundle| {
                        joinsplits_hash(
                            tx.consensus_branch_id,
                            &bundle.joinsplits,
                            &bundle.joinsplit_pubkey,
                        )
                    })
            },
            |digests| digests.joinsplits,
        );
        match joinsplits {
            Some(digest) => h.update(digest.as_bytes()),
            None => h.update(&[0; 32]),
        };

        if tx.version.has_sapling() {
            let sapling_spends = precomputed.map_or_else(
                || {
                    tx.sapling_bundle
                        .as_ref()
                        .filter(|bundle| !bundle.shielded_spends().is_empty())
                        .map(|bundle| sapling_spends_hash(bundle.shielded_spends()))
                },
                |digests| digests.sapling_spends,
            );
            match sapling_spends {
                Some(digest) => h.update(digest.as_bytes()),
                None => h.update(&[0; 32]),
            };

            let sapling_outputs = precomputed.map_or_else(
                || {
                    tx.sapling_bundle
                        .as_ref()
                        .filter(|bundle| !bundle.shielded_outputs().is_empty())
                        .map(|bundle| sapling_outputs_hash(bundle.shielded_outputs()))
                },
                |digests| digests.sapling_outputs,
            );
            match sapling_outputs {
                Some(digest) => h.update(digest.as_bytes()),
                None => h.update(&[0; 32]),
            };
        }
        h.update(&tx.lock_time.to_le_bytes());
        h.update(&u32::from(tx.expiry_height).to_le_bytes());
        if tx.version.has_sapling() {
            h.update(&tx.sapling_value_balance().to_i64_le_bytes());
        }
        h.update(&u32::from(hash_type).to_le_bytes());

        match signable_input {
            SignableInput::Shielded => (),
            SignableInput::Transparent(input) => {
                if let Some(bundle) = tx.transparent_bundle.as_ref() {
                    let mut data = vec![];
                    bundle.vin[*input.index()]
                        .prevout()
                        .write(&mut data)
                        .unwrap();
                    input.script_code().write(&mut data).unwrap();
                    data.extend_from_slice(&input.value().to_i64_le_bytes());
                    data.extend_from_slice(&bundle.vin[*input.index()].sequence().to_le_bytes());
                    h.update(&data);
                } else {
                    panic!(
                        "A request has been made to sign a transparent input, but none are present."
                    );
                }
            }
        }

        h.finalize()
    } else {
        panic!("Signature hashing for pre-overwinter transactions is not supported.")
    }
}

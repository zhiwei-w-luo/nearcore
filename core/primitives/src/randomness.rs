use crate::hash::{hash, CryptoHash};
use crate::merkle::{merklize, verify_path, MerklePath};
use crate::types::{BlockHeightDelta, MerkleHash, NumSeats, ShardId};
use crate::validator_signer::ValidatorSigner;
use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use near_crypto::randomness::{
    generate_shares, CompressedShare, DecryptedShare, DecryptionFailureProof, EncryptedShare,
    Params, PublicShares, RandomEpoch, ValidatedPublicShares, ValidatedPublicSharesCompressed,
};

#[derive(BorshSerialize, BorshDeserialize, Serialize, Hash, Eq, PartialEq, Clone, Debug)]
pub struct DkgDecryptedSecretShare(pub [u8; 32]);

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct DkgValidatedPublicShares {
    pub producer_ordinal: u64,
    pub validated_shares: ValidatedPublicShares,
    pub merkle_proofs: Vec<MerklePath>,
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug, Clone)]
pub struct DkgValidatedPublicSharesCompressed {
    pub producer_ordinal: u64,
    // These fields are private, so that the compressed datastructure is never used on its own
    compressed_validated_shares: ValidatedPublicSharesCompressed,
    merkle_proofs: Vec<MerklePath>,
}

impl DkgValidatedPublicShares {
    pub fn compress(self) -> DkgValidatedPublicSharesCompressed {
        DkgValidatedPublicSharesCompressed {
            producer_ordinal: self.producer_ordinal,
            compressed_validated_shares: self.validated_shares.compress(),
            merkle_proofs: self.merkle_proofs,
        }
    }
}

impl DkgValidatedPublicSharesCompressed {
    pub fn decompress(self) -> DkgValidatedPublicShares {
        DkgValidatedPublicShares {
            producer_ordinal: self.producer_ordinal,
            validated_shares: self.compressed_validated_shares.decompress(),
            merkle_proofs: self.merkle_proofs,
        }
    }
}

/// The phases of the DKG for randomness during a particular epoch
#[derive(BorshSerialize, BorshDeserialize, Serialize, PartialEq, Eq, Clone, Debug, Copy)]
pub enum RandomnessDKGPhase {
    /// The participants of the current epoch are committing to their public / secret shares
    Commit,
    /// The participants of the next epoch are challenging the invalid commitments
    /// Challenges during the `Commit` phase are also possible.
    Challenge,
    /// The public keys are being aggregated, the parameter is the first ordinal for whom the
    /// aggregated PK is not known
    Aggregate(u64),
    /// The DKG is completed. The epoch cannot be switches until this phase
    Completed,
}

/// The DKG-related information for one seat
#[derive(BorshSerialize, BorshDeserialize, Serialize, Default, PartialEq, Eq, Clone, Debug)]
pub struct BlockRandomnessDKGCommitmentInfo {
    /// Which shard did the participant send their commitment info via
    pub shard_id: ShardId,
    /// The merkle proof of the public and secret shares
    pub public_shares_merkle_root: MerkleHash,
    pub secret_shares_merkle_root: MerkleHash,
    /// Whether the commitment for the seat was challenged
    pub was_challenged: bool,
}

/// Contains all the information related to the randomness that is stored in the block body.
/// The struct is included in the block, and the hash of the struct is committed in the block header.
#[derive(BorshSerialize, BorshDeserialize, Serialize, PartialEq, Eq, Clone, Debug, Default)]
pub struct BlockRandomnessDKGInfo {
    /// The aggregated public shares to be used in the current epoch
    pub this_epoch_shares: Vec<CompressedShare>,
    /// The commitment information from each block producer of this epoch, indexed by the
    /// block producer ID. Only stores elements up the last entry with non-None `commitment_info`
    pub commitment_infos: Vec<Option<BlockRandomnessDKGCommitmentInfo>>,
    /// The aggregated values for the next epoch, indexed by the part ordinal. Only stores entry
    /// for the elements aggregated so far.
    /// Is empty if there were no commitments, since there's nothing to aggregate.
    pub next_epoch_aggregated_shares: Vec<CompressedShare>,
}

impl BlockRandomnessDKGInfo {
    pub fn new() -> Self {
        Self {
            this_epoch_shares: vec![],
            commitment_infos: vec![],
            next_epoch_aggregated_shares: vec![],
        }
    }

    /// Returns whether the randomness beacon should be producing values in the epoch as of this block.
    pub fn is_beacon_enabled(&self) -> bool {
        !self.this_epoch_shares.is_empty()
    }

    /// Returns whether the randomness beacon should be producing values in the epoch as of next block.
    /// The randomness beacon is producing values if the DKG in the previous epoch was successful.
    /// Thus, the first epoch never has randomness beacon enabled. Optimistically each consecutive
    /// epoch should have DKG enabled, but we do not make such an assumption.
    pub fn is_beacon_enabled_next_block(&self, is_epoch_switch: bool) -> bool {
        if is_epoch_switch {
            !self.next_epoch_aggregated_shares.is_empty()
        } else {
            !self.this_epoch_shares.is_empty()
        }
    }

    pub fn has_info(&self, ordinal: usize) -> bool {
        self.commitment_infos.len() > ordinal && self.commitment_infos[ordinal].is_some()
    }

    pub fn has_valid_info(&self, ordinal: usize) -> bool {
        self.commitment_infos.len() > ordinal
            && self.commitment_infos[ordinal].is_some()
            && !self.commitment_infos[ordinal].as_ref().unwrap().was_challenged
    }

    pub fn hash(&self) -> CryptoHash {
        hash(&self.try_to_vec().expect("Failed to serialize"))
    }

    /// Computes the phase of the DKG. `Commit` and `Challenge` phases are defined by the number
    /// of heights from the epoch start, while the `Aggregate` and `Completed` are differentiated
    /// based on whether we have all the public keys aggregated.
    pub fn compute_phase(
        &self,
        epoch_length: BlockHeightDelta,
        heights_from_epoch_start: BlockHeightDelta,
        num_seats: NumSeats,
    ) -> RandomnessDKGPhase {
        let commit_phase_end = epoch_length / 10;
        let challenge_phase_end = epoch_length * 9 / 10;

        if heights_from_epoch_start < commit_phase_end {
            RandomnessDKGPhase::Commit
        } else if heights_from_epoch_start < challenge_phase_end {
            RandomnessDKGPhase::Challenge
        } else {
            // If there's at least one committed, not challenged seat for which we haven't aggregated
            // the value yet, continue the `Aggregate` phase
            if self.is_in_progress(num_seats) {
                RandomnessDKGPhase::Aggregate(self.next_epoch_aggregated_shares.len() as NumSeats)
            } else {
                RandomnessDKGPhase::Completed
            }
        }
    }

    /// Returns whether the DKG is in the state in which an epoch switch is not possible.
    /// An epoch switch can occur either if the commitment infos are empty (in which case the beacon
    /// is disabled for the next epoch), or if the aggregation has completed
    pub fn is_in_progress(&self, num_seats: NumSeats) -> bool {
        self.commitment_infos.len() > 0
            && (self.next_epoch_aggregated_shares.len() as NumSeats) < (num_seats / 2) + 1
    }

    pub fn aggregate(&mut self, shares_with_proofs: &Vec<&CompressedShareWithProof>) {
        let mut count_valid = 0;

        for i in 0..self.commitment_infos.len() {
            if self.has_valid_info(i) {
                count_valid += 1;
            }
        }

        debug_assert_eq!(count_valid, shares_with_proofs.len());

        let ristretto_point = if shares_with_proofs.len() == 0 {
            RistrettoPoint::identity()
        } else {
            // We don't accept chunk headers that have compressed points in them that can't be
            // decompressed, thus an unwrap here is safe.
            // (see `ChunkRandomnessDkgInfoHeader::validate`)
            shares_with_proofs
                .iter()
                .map(|share| {
                    CompressedRistretto::from_slice(share.share.as_ref()).decompress().unwrap()
                })
                .sum()
        };

        self.next_epoch_aggregated_shares.push(CompressedShare::from_point(&ristretto_point));
    }

    /// Validates the challenge with merkle proofs against the DKG info body
    ///
    /// # Arguments:
    /// `challenge` - the challenge to validate
    /// `challenger_pk` - the public key of the challenger. Must be the public key of the block
    ///                   producer that is responsible for the part `challenge.part_ord` in the
    ///                   next epoch.
    pub fn validate_challenge(
        &self,
        challenge: &DecryptionFailureProofWithMerkleProofs,
        challenger_pk: &near_crypto::vrf::PublicKey,
    ) -> Result<(), ChunkRandomnessDkgInfoValidationError> {
        let DecryptionFailureProofWithMerkleProofs {
            part_ord,
            public_share,
            encrypted_secret_share,
            public_share_merkle_proof,
            secret_share_merkle_proof,
            decryption_failure_proof,
        } = challenge;
        let part_ord = *part_ord as usize;

        if part_ord >= self.commitment_infos.len() {
            return Err(ChunkRandomnessDkgInfoValidationError::ChallengeOfMissingCommit);
        }
        let commitment = self.commitment_infos[part_ord].as_ref();
        if let Some(commitment) = commitment {
            if !verify_path(
                commitment.public_shares_merkle_root,
                public_share_merkle_proof,
                public_share,
            ) {
                return Err(ChunkRandomnessDkgInfoValidationError::InvalidMerkleProof);
            }
            if !verify_path(
                commitment.secret_shares_merkle_root,
                secret_share_merkle_proof,
                encrypted_secret_share,
            ) {
                return Err(ChunkRandomnessDkgInfoValidationError::InvalidMerkleProof);
            }

            if !ValidatedPublicShares::is_valid_static(
                public_share.to_point(),
                &EncryptedShare(encrypted_secret_share.0),
                challenger_pk,
                &decryption_failure_proof,
            ) {
                return Err(ChunkRandomnessDkgInfoValidationError::InvalidDecryptionFailureProof);
            }

            Ok(())
        } else {
            Err(ChunkRandomnessDkgInfoValidationError::ChallengeOfMissingCommit)
        }
    }

    /// Returns a `RandomEpoch` for the aggregated shares for the next block.
    /// Say the chain is `B<-B'` (`B`'s parent is `B'`). When `B'` is produced, to generate a rand
    /// reveal one must know the epoch as of `B`. It would be the same epoch as as of `B'` if they
    /// are in the same epoch, and the next one if they are in two different epochs.
    /// This method contains the logic to fetch the random epoch as of `B` given the dkg info in `B'`
    ///
    /// # Arguments
    /// `num_seats`         - number of seats in the epoch
    /// `is_epoch_boundary` - whether the next block is in a different epoch that the block that
    ///                       corresponds to this DKG info. In such a case the next epoch shares
    ///                       are returned.
    ///
    /// # Returns
    /// The `RandomEpoch` if there are public shares for the corresponding epoch, otherwise None
    pub fn get_next_random_epoch(
        &self,
        num_seats: NumSeats,
        is_epoch_boundary: bool,
    ) -> Option<RandomEpoch> {
        let params = Params::new(num_seats as usize, num_seats as usize / 2 + 1);
        let shares = if is_epoch_boundary {
            self.next_epoch_aggregated_shares.clone()
        } else {
            self.this_epoch_shares.clone()
        };

        if shares.is_empty() {
            return None;
        }

        let validated_shares = ValidatedPublicSharesCompressed(shares).decompress();

        Some(RandomEpoch::from_shares(params, vec![validated_shares].into_iter()))
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum ChunkRandomnessDkgInfoValidationError {
    WrongInfoType,
    InvalidN,
    InvalidK,
    PublicShareValidationFailed,
    /// Header with Aggregate has ordinal that doesn't match the expected ordinal in the block info
    IncorrectOrdinal,
    /// Header with Aggregate doesn't has number of values different than committed but not challenged
    /// in the shard
    WrongSetOfValues,
    /// Header with Commit has merkle roots that don't match the roots of the actual data in the
    /// body
    InvalidMerkleRoot,
    /// Header with Aggregate has a value with a merkle proof that doesn't match the hash stored in
    /// the block info
    InvalidMerkleProof,
    /// One of the compressed points cannot be decompressed
    DecompressionFailed,
    /// Challenge contains a proof that doesn't pass validation
    InvalidDecryptionFailureProof,
    /// Challenge for a block producer that hasn't committed
    ChallengeOfMissingCommit,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Eq, PartialEq, Clone, Debug)]
pub enum ChunkRandomnessDkgInfoBody {
    None,
    Commit {
        // Public shares is just a vec that is verbatim `PublicShares`
        public_shares: Vec<u8>,
        encrypted_secret_shares: Vec<EncryptedShare>,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Eq, PartialEq, Clone, Debug)]
pub struct CompressedShareWithProof {
    producer_ordinal: u64,
    share: CompressedShare,
    proof: MerklePath,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Eq, PartialEq, Clone, Debug)]
pub struct DecryptionFailureProofWithMerkleProofs {
    pub part_ord: NumSeats,
    pub decryption_failure_proof: DecryptionFailureProof,
    pub public_share: CompressedShare,
    pub encrypted_secret_share: EncryptedShare,
    pub public_share_merkle_proof: MerklePath,
    pub secret_share_merkle_proof: MerklePath,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Eq, PartialEq, Clone, Debug)]
pub enum ChunkRandomnessDkgInfoHeader {
    None,
    Commit { pk_merkle_root: MerkleHash, sk_merkle_root: MerkleHash },
    Aggregate { ordinal: u64, values: Vec<CompressedShareWithProof> },
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub struct DkgEncryptedSecretShareWithMerkleProofs {
    pub part_ord: u64,
    pub public_share: CompressedShare,
    pub encrypted_secret_share: EncryptedShare,
    pub public_share_merkle_proof: MerklePath,
    pub secret_share_merkle_proof: MerklePath,
}

impl ChunkRandomnessDkgInfoBody {
    /// Generates the shard DKG body from the previous block DKG state and information about the current
    /// block producer
    ///
    /// # Arguments
    /// * `prev_dkg_info`  - DKG info from the previous block (on top of which the chunk will be built)
    /// * `prev_dkg_phase` - the phase derived from the `prev_dkg_info`
    /// * `bp_ordinal`     - the ordinal of the block producer in the current epoch (0 < `ordinal` < `num_seats`)
    /// * `my_pk`          - public key of the block producer
    /// * `target_pks`     - public keys of the recipient block producers per seat
    pub fn from_prev_dkg_info_and_public_key(
        prev_dkg_info: &BlockRandomnessDKGInfo,
        prev_dkg_phase: RandomnessDKGPhase,
        bp_ordinal: Option<usize>,
        my_pk: &near_crypto::vrf::PublicKey,
        target_pks: &Vec<near_crypto::vrf::PublicKey>,
    ) -> ChunkRandomnessDkgInfoBody {
        if let (RandomnessDKGPhase::Commit, Some(bp_ordinal)) = (prev_dkg_phase, bp_ordinal) {
            if !prev_dkg_info.has_info(bp_ordinal) {
                let n = target_pks.len();
                let k = n / 2 + 1;

                assert_ne!(n, 0);

                let (public_share, secret_share) = generate_shares(Params::new(n, k), my_pk);

                assert_eq!(public_share.0.len(), 32 * k + 64);

                let encrypted_secret_shares = target_pks
                    .iter()
                    .enumerate()
                    .map(|(ordinal, pk)| secret_share.encrypt(ordinal, pk))
                    .collect();

                ChunkRandomnessDkgInfoBody::Commit {
                    public_shares: public_share.0.to_vec(),
                    encrypted_secret_shares,
                }
            } else {
                ChunkRandomnessDkgInfoBody::None
            }
        } else {
            ChunkRandomnessDkgInfoBody::None
        }
    }

    /// Validates the shard DKG body given the previous block DKG state.
    ///
    /// # Arguments
    /// * `prev_dkg_info`  - DKG info from the previous block (on top of which the chunk will be built)
    /// * `prev_dkg_phase` - the phase derived from the `prev_dkg_info`
    /// * `producer_ordinal` - the ordinal of the block producer in the current epoch who produced
    ///                      the chunk
    /// * `producer_pk`    - the public key of the block producer who produced the chunk
    /// * `num_bps_next_epoch` - the number of block producers in the next epoch
    ///
    /// # Returns
    /// Any error that can be validated by other block producers results in an Err, and the chunk
    /// that includes the dkg body must be marked as invalid.
    /// This method doesn't try to decrypt any shares. A share decryption failure doesn't make the
    /// chunk invalid, because without extra information cannot be validated by other block producers
    /// In case of successful validation of the commitment to a public/secret shares pair, returns
    /// validated public shares and the corresponding merkle proofs.
    #[must_use]
    pub fn validate(
        &self,
        prev_dkg_info: &BlockRandomnessDKGInfo,
        prev_dkg_phase: RandomnessDKGPhase,
        producer_ordinal: usize,
        producer_pk: &near_crypto::vrf::PublicKey,
        num_bps_next_epoch: NumSeats,
    ) -> Result<Option<DkgValidatedPublicShares>, ChunkRandomnessDkgInfoValidationError> {
        match prev_dkg_phase {
            RandomnessDKGPhase::Commit if !prev_dkg_info.has_info(producer_ordinal) => {
                if let ChunkRandomnessDkgInfoBody::Commit {
                    public_shares,
                    encrypted_secret_shares,
                } = self
                {
                    let n = num_bps_next_epoch as usize;
                    let k = n / 2 + 1;

                    if public_shares.len() != 32 * k + 64 {
                        Err(ChunkRandomnessDkgInfoValidationError::InvalidK)
                    } else if encrypted_secret_shares.len() != n {
                        Err(ChunkRandomnessDkgInfoValidationError::InvalidN)
                    } else {
                        let validated_pk = PublicShares(public_shares.clone().into_boxed_slice())
                            .validate(producer_pk);

                        if let Some(validated_pk) = validated_pk {
                            let merkle_proofs = merklize(
                                &validated_pk.expand_and_compress(encrypted_secret_shares.len()),
                            )
                            .1;
                            Ok(Some(DkgValidatedPublicShares {
                                producer_ordinal: producer_ordinal as u64,
                                validated_shares: validated_pk,
                                merkle_proofs,
                            }))
                        } else {
                            Err(ChunkRandomnessDkgInfoValidationError::PublicShareValidationFailed)
                        }
                    }
                } else {
                    Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                }
            }
            _ => {
                if let &ChunkRandomnessDkgInfoBody::None = self {
                    Ok(None)
                } else {
                    Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                }
            }
        }
    }

    pub fn get_expanded_compressed_shares_without_validation(
        &self,
    ) -> Result<(Vec<CompressedShare>, Vec<EncryptedShare>), ()> {
        Ok(
            if let ChunkRandomnessDkgInfoBody::Commit { public_shares, encrypted_secret_shares } =
                &self
            {
                (
                match PublicShares(public_shares.clone().into_boxed_slice()).skip_validation() {
                    Some(x) => x,
                    None => return Err(()),
                }
                .expand_and_compress(encrypted_secret_shares.len()),
                encrypted_secret_shares.clone(),
            )
            } else {
                (vec![], vec![])
            },
        )
    }
}

impl ChunkRandomnessDkgInfoHeader {
    /// Generates the shard DKG header from the previous block DKG state, the shard dkg body, and
    /// optionally committed public keys
    ///
    /// # Arguments
    /// * `prev_dkg_info`  - DKG info from the previous block (on top of which the chunk will be built)
    /// * `prev_dkg_phase` - the phase derived from the `prev_dkg_info`
    /// * `dkg_body`       - the shard DKG body that corresponds to the header being created
    /// * `producer_ordinal` - the ordinal of the block producer in the current epoch who produced
    ///                      the chunk
    /// * `producer_pk`    - the public key of the block producer who produced the chunk
    /// * `validated_shares` - if the `prev_dkg_phase` is aggregate, contains all the validated pks
    ///                      that were committed during the commit phase
    ///
    pub fn from_prev_dkg_info_and_body(
        prev_dkg_info: &BlockRandomnessDKGInfo,
        prev_dkg_phase: RandomnessDKGPhase,
        dkg_body: &ChunkRandomnessDkgInfoBody,
        producer_pk: &near_crypto::vrf::PublicKey,
        validated_shares: Option<&Vec<DkgValidatedPublicSharesCompressed>>,
    ) -> Option<ChunkRandomnessDkgInfoHeader> {
        Some(match prev_dkg_phase {
            RandomnessDKGPhase::Commit => {
                if let ChunkRandomnessDkgInfoBody::Commit {
                    public_shares,
                    encrypted_secret_shares,
                } = dkg_body
                {
                    let validated_public_shares =
                        match PublicShares(public_shares.clone().into_boxed_slice())
                            .validate(producer_pk)
                        {
                            Some(x) => x,
                            None => return None,
                        };

                    ChunkRandomnessDkgInfoHeader::Commit {
                        pk_merkle_root: merklize(
                            validated_public_shares
                                .expand_and_compress(encrypted_secret_shares.len())
                                .as_ref(),
                        )
                        .0,
                        sk_merkle_root: merklize(encrypted_secret_shares.as_ref()).0,
                    }
                } else {
                    ChunkRandomnessDkgInfoHeader::None
                }
            }
            RandomnessDKGPhase::Aggregate(ordinal) => match validated_shares {
                Some(validated_pks) => ChunkRandomnessDkgInfoHeader::Aggregate {
                    ordinal,
                    values: validated_pks
                        .iter()
                        .filter_map(|x| {
                            if prev_dkg_info.has_valid_info(x.producer_ordinal as usize) {
                                Some(CompressedShareWithProof {
                                    producer_ordinal: x.producer_ordinal,
                                    share: x.compressed_validated_shares.0[ordinal as usize],
                                    proof: x.merkle_proofs[ordinal as usize].clone(),
                                })
                            } else {
                                None
                            }
                        })
                        .collect(),
                },
                None => return None,
            },
            _ => ChunkRandomnessDkgInfoHeader::None,
        })
    }

    /// Validates the DKG header in a particular chunk. Checks that the type of the header matches
    /// the phase of the DKG, as well as the correctness of the proofs in `Aggregate` headers.
    /// The shard DKG body is optional, if provided, also validates the merkle proofs in `Commit`
    /// headers, and ensures that the body and the header are consistent with each other.
    ///
    /// # Arguments
    /// * `shard_id`       - the shard ID the chunk is in
    /// * `prev_dkg_info`  - DKG info from the previous block (on top of which the chunk will be built)
    /// * `prev_dkg_phase` - the phase derived from the `prev_dkg_info`
    /// * `shard_dkg_body` - (optional) the shard DKG body that corresponds to the header being created
    /// * `producer_ordinal` - the ordinal of the block producer in the current epoch who produced
    ///                      the chunk
    /// * `producer_pk`    - the public key of the block producer who produced the chunk
    pub fn validate(
        &self,
        shard_id: ShardId,
        prev_dkg_info: &BlockRandomnessDKGInfo,
        prev_dkg_phase: RandomnessDKGPhase,
        shard_dkg_body: Option<&ChunkRandomnessDkgInfoBody>,
        producer_ordinal: usize,
        producer_pk: &near_crypto::vrf::PublicKey,
    ) -> Result<(), ChunkRandomnessDkgInfoValidationError> {
        match prev_dkg_phase {
            RandomnessDKGPhase::Commit if !prev_dkg_info.has_info(producer_ordinal) => {
                match shard_dkg_body {
                    // The body is not provided, skip the validation of the body. The header must be
                    // `Commit` or `None`
                    None => match self {
                        ChunkRandomnessDkgInfoHeader::None => Ok(()),
                        ChunkRandomnessDkgInfoHeader::Commit { .. } => Ok(()),
                        _ => Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType),
                    },
                    // The body is provided, validate the merkle proofs
                    Some(shard_dkg_body) => match shard_dkg_body {
                        ChunkRandomnessDkgInfoBody::None => {
                            return if self == &ChunkRandomnessDkgInfoHeader::None {
                                Ok(())
                            } else {
                                Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                            };
                        }
                        ChunkRandomnessDkgInfoBody::Commit {
                            public_shares,
                            encrypted_secret_shares,
                        } => match self {
                            ChunkRandomnessDkgInfoHeader::Commit {
                                pk_merkle_root,
                                sk_merkle_root,
                            } => {
                                let validated_public_shares =
                                        match PublicShares(public_shares.clone().into_boxed_slice())
                                            .validate(producer_pk)
                                            {
                                                Some(x) => x,
                                                None => return Err(ChunkRandomnessDkgInfoValidationError::PublicShareValidationFailed),
                                            }.expand_and_compress(encrypted_secret_shares.len());

                                if pk_merkle_root == &merklize(validated_public_shares.as_ref()).0
                                    && sk_merkle_root
                                        == &merklize(encrypted_secret_shares.as_ref()).0
                                {
                                    Ok(())
                                } else {
                                    Err(ChunkRandomnessDkgInfoValidationError::InvalidMerkleRoot)
                                }
                            }
                            _ => Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType),
                        },
                    },
                }
            }
            RandomnessDKGPhase::Aggregate(expected_ordinal) => {
                if let ChunkRandomnessDkgInfoHeader::Aggregate { ordinal, values } = self {
                    if &expected_ordinal != ordinal {
                        Err(ChunkRandomnessDkgInfoValidationError::IncorrectOrdinal)
                    } else {
                        let mut next_value_ord = 0;
                        for (i, commitment_info) in
                            prev_dkg_info.commitment_infos.iter().enumerate()
                        {
                            let commitment_info = match commitment_info {
                                None => continue,
                                Some(commitment_info) => commitment_info,
                            };

                            if commitment_info.was_challenged {
                                continue;
                            }

                            if commitment_info.shard_id == shard_id {
                                if next_value_ord >= values.len() {
                                    return Err(
                                        ChunkRandomnessDkgInfoValidationError::WrongSetOfValues,
                                    );
                                }

                                let value = &values[next_value_ord];
                                if value.producer_ordinal as usize != i {
                                    return Err(
                                        ChunkRandomnessDkgInfoValidationError::WrongSetOfValues,
                                    );
                                }

                                if CompressedRistretto::from_slice(value.share.as_ref())
                                    .decompress()
                                    .is_none()
                                {
                                    return Err(
                                        ChunkRandomnessDkgInfoValidationError::DecompressionFailed,
                                    );
                                }

                                if !verify_path(
                                    commitment_info.public_shares_merkle_root,
                                    &value.proof,
                                    &value.share,
                                ) {
                                    return Err(
                                        ChunkRandomnessDkgInfoValidationError::InvalidMerkleProof,
                                    );
                                }

                                next_value_ord += 1;
                            }
                        }

                        if next_value_ord != values.len() {
                            return Err(ChunkRandomnessDkgInfoValidationError::WrongSetOfValues);
                        }

                        Ok(())
                    }
                } else {
                    Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                }
            }
            _ => {
                if let &ChunkRandomnessDkgInfoHeader::None = self {
                    // If the body is not provided, or if the body is None, the validation is
                    // successful. If the body is non-None, the validation fails
                    match shard_dkg_body {
                        None => Ok(()),
                        Some(ChunkRandomnessDkgInfoBody::None) => Ok(()),
                        _ => Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType),
                    }
                } else {
                    Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                }
            }
        }
    }

    pub fn is_commit(&self) -> bool {
        match self {
            ChunkRandomnessDkgInfoHeader::Commit { .. } => true,
            _ => false,
        }
    }
}

impl DkgEncryptedSecretShareWithMerkleProofs {
    pub fn decrypt_share(
        &self,
        signer: &dyn ValidatorSigner,
    ) -> Result<DecryptedShare, DecryptionFailureProofWithMerkleProofs> {
        signer
            .decode_share(&EncryptedShare(self.encrypted_secret_share.0), &self.public_share.0)
            .map_err(|decryption_failure_proof| DecryptionFailureProofWithMerkleProofs {
                part_ord: self.part_ord,
                decryption_failure_proof,
                public_share: self.public_share.clone(),
                encrypted_secret_share: self.encrypted_secret_share.clone(),
                public_share_merkle_proof: self.public_share_merkle_proof.clone(),
                secret_share_merkle_proof: self.secret_share_merkle_proof.clone(),
            })
    }
}

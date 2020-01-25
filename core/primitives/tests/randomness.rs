#[cfg(test)]
mod tests {
    use near_crypto::randomness::{Params, RandomEpoch};
    use near_primitives::randomness::{
        BlockRandomnessDKGCommitmentInfo, BlockRandomnessDKGInfo, ChunkRandomnessDkgInfoBody,
        ChunkRandomnessDkgInfoHeader, ChunkRandomnessDkgInfoValidationError, RandomnessDKGPhase,
    };
    use near_primitives::types::{NumSeats, NumShards};

    /// Tests various basic scenarios of creating and validating shard DKG bodies and headers, as well
    /// as their interaction with the block info
    #[test]
    fn test_dkg_header_body_creation_and_validation() {
        const PREV_EPOCH_BPS: usize = 15;
        const NEXT_EPOCH_BPS: usize = 10;
        const NEXT_K: usize = NEXT_EPOCH_BPS / 2 + 1;

        // We will make one BP to skip their commitment, and one to get challenged, and then do
        // basic verification that it doesn't confuse the aggregation process.
        const SKIP_BP: usize = 5;
        const CHALLENGE_BP: usize = 2;

        let prev_epoch_sks =
            (0..PREV_EPOCH_BPS).map(|_| near_crypto::vrf::SecretKey::random()).collect::<Vec<_>>();
        let next_epoch_sks =
            (0..NEXT_EPOCH_BPS).map(|_| near_crypto::vrf::SecretKey::random()).collect::<Vec<_>>();

        let prev_epoch_pks = prev_epoch_sks.iter().map(|sk| sk.public_key()).collect::<Vec<_>>();
        let next_epoch_pks = next_epoch_sks.iter().map(|sk| sk.public_key()).collect::<Vec<_>>();

        let mut last_block_dkg_info = BlockRandomnessDKGInfo::default();
        let last_block_dkg_phase =
            last_block_dkg_info.compute_phase(100, 5, NEXT_EPOCH_BPS as NumSeats);
        assert_eq!(last_block_dkg_phase, RandomnessDKGPhase::Commit);

        let mut validated_public_sharess = vec![];

        for seat_ord in 0..PREV_EPOCH_BPS {
            // Create a DKG body. Expect it to have a commitment info.
            let dkg_body = ChunkRandomnessDkgInfoBody::from_prev_dkg_info_and_public_key(
                &last_block_dkg_info,
                last_block_dkg_phase,
                Some(seat_ord),
                &prev_epoch_pks[seat_ord],
                &next_epoch_pks,
            );

            let validated_shares = match dkg_body {
                ChunkRandomnessDkgInfoBody::None => {
                    assert!(false);
                    return;
                }
                ChunkRandomnessDkgInfoBody::Commit { .. } => {
                    // Make sure it can be validated
                    let validation_result = dkg_body.validate(
                        &last_block_dkg_info,
                        last_block_dkg_phase,
                        seat_ord,
                        &prev_epoch_pks[seat_ord],
                        NEXT_EPOCH_BPS as NumSeats,
                    );

                    // Expect that the validation succeeded and returned us some validated shares
                    let validated_shares = validation_result.unwrap().unwrap();

                    // The same DKG body should not pass the validation with another phase, or another number of seats
                    assert_eq!(
                        dkg_body.validate(
                            &last_block_dkg_info,
                            // Pass wrong phase
                            RandomnessDKGPhase::Challenge,
                            seat_ord,
                            &prev_epoch_pks[seat_ord],
                            NEXT_EPOCH_BPS as NumSeats,
                        ),
                        Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                    );
                    assert_eq!(
                        dkg_body.validate(
                            &last_block_dkg_info,
                            last_block_dkg_phase,
                            seat_ord,
                            &prev_epoch_pks[seat_ord],
                            // Pass prev epoch bps instead of next
                            PREV_EPOCH_BPS as NumSeats,
                        ),
                        Err(ChunkRandomnessDkgInfoValidationError::InvalidK)
                    );

                    validated_shares
                }
            };

            validated_public_sharess.push(validated_shares);

            // Create a header based on the body
            let dkg_header = ChunkRandomnessDkgInfoHeader::from_prev_dkg_info_and_body(
                &last_block_dkg_info,
                last_block_dkg_phase,
                &dkg_body,
                &prev_epoch_pks[seat_ord],
                None,
            );

            let (public_shares_hash, secret_shares_hash) = match dkg_header {
                Some(ChunkRandomnessDkgInfoHeader::Commit { pk_merkle_root, sk_merkle_root }) => {
                    (pk_merkle_root, sk_merkle_root)
                }
                _ => {
                    assert!(false);
                    return;
                }
            };
            let dkg_header = dkg_header.unwrap();

            // Validate providing the body...
            assert_eq!(
                dkg_header.validate(
                    0, // ShardId doesn't matter for Commit
                    &last_block_dkg_info,
                    last_block_dkg_phase,
                    Some(&dkg_body),
                    seat_ord,
                    &prev_epoch_pks[seat_ord]
                ),
                Ok(())
            );

            // And not providing the body...
            assert_eq!(
                dkg_header.validate(
                    0, // ShardId doesn't matter for Commit
                    &last_block_dkg_info,
                    last_block_dkg_phase,
                    None,
                    seat_ord,
                    &prev_epoch_pks[seat_ord]
                ),
                Ok(())
            );

            // Should not work for a different phase
            assert!(dkg_header
                .validate(
                    0, // ShardId doesn't matter for Commit
                    &last_block_dkg_info,
                    RandomnessDKGPhase::Challenge,
                    None,
                    seat_ord,
                    &prev_epoch_pks[seat_ord]
                )
                .is_err());

            // Also headers that are not Commit should fail validation as well, with or without the body
            let challenge_header =
                ChunkRandomnessDkgInfoHeader::Aggregate { ordinal: 0, values: vec![] };
            for body in vec![None, Some(&dkg_body)].into_iter() {
                assert_eq!(
                    challenge_header.validate(
                        0,
                        &last_block_dkg_info,
                        last_block_dkg_phase,
                        body,
                        seat_ord,
                        &prev_epoch_pks[seat_ord]
                    ),
                    Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                );
            }

            if seat_ord == SKIP_BP {
                // Set the bit in the body
                last_block_dkg_info.commitment_infos.push(None);

                continue;
            }

            // Set the bit in the body
            last_block_dkg_info.commitment_infos.push(Some(BlockRandomnessDKGCommitmentInfo {
                shard_id: seat_ord as NumShards % 4,
                public_shares_merkle_root: public_shares_hash,
                secret_shares_merkle_root: secret_shares_hash,
                was_challenged: false,
            }));

            // The validation against the old body must fail, because the bp is no longer expected to
            // provide a commit
            assert_eq!(
                dkg_body.validate(
                    &last_block_dkg_info,
                    last_block_dkg_phase,
                    seat_ord,
                    &prev_epoch_pks[seat_ord],
                    NEXT_EPOCH_BPS as NumSeats,
                ),
                Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
            );

            // Now the body for the same bp should be None
            let new_dkg_body = ChunkRandomnessDkgInfoBody::from_prev_dkg_info_and_public_key(
                &last_block_dkg_info,
                last_block_dkg_phase,
                Some(seat_ord),
                &prev_epoch_pks[seat_ord],
                &next_epoch_pks,
            );
            assert_eq!(new_dkg_body, ChunkRandomnessDkgInfoBody::None);

            // The validation against the old header must fail, because the bp is no longer expected to
            // provide a commit
            for body in vec![Some(&dkg_body), Some(&new_dkg_body), None].into_iter() {
                assert_eq!(
                    dkg_header.validate(
                        0, // ShardId doesn't matter for Commit
                        &last_block_dkg_info,
                        last_block_dkg_phase,
                        body,
                        seat_ord,
                        &prev_epoch_pks[seat_ord]
                    ),
                    Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                );
            }

            // Create a header based on the new body
            let dkg_header = ChunkRandomnessDkgInfoHeader::from_prev_dkg_info_and_body(
                &last_block_dkg_info,
                last_block_dkg_phase,
                &new_dkg_body,
                &prev_epoch_pks[seat_ord],
                None,
            )
            .unwrap();

            assert_eq!(dkg_header, ChunkRandomnessDkgInfoHeader::None);

            for (body, expect_pass) in
                vec![(Some(&dkg_body), false), (Some(&new_dkg_body), true), (None, true)]
                    .into_iter()
            {
                assert_eq!(
                    dkg_header.validate(
                        0, // ShardId doesn't matter for Commit
                        &last_block_dkg_info,
                        last_block_dkg_phase,
                        body,
                        seat_ord,
                        &prev_epoch_pks[seat_ord]
                    ),
                    if expect_pass {
                        Ok(())
                    } else {
                        Err(ChunkRandomnessDkgInfoValidationError::WrongInfoType)
                    }
                );
            }
        }

        // Move to Challenge phase, verify that no blocks / headers are produced
        let last_block_dkg_phase =
            last_block_dkg_info.compute_phase(100, 15, NEXT_EPOCH_BPS as NumSeats);
        assert_eq!(last_block_dkg_phase, RandomnessDKGPhase::Challenge);

        for seat_ord in 0..PREV_EPOCH_BPS {
            let dkg_body = ChunkRandomnessDkgInfoBody::from_prev_dkg_info_and_public_key(
                &last_block_dkg_info,
                last_block_dkg_phase,
                Some(seat_ord),
                &prev_epoch_pks[seat_ord],
                &next_epoch_pks,
            );
            assert_eq!(dkg_body, ChunkRandomnessDkgInfoBody::None);

            // Create a header based on the new body
            let dkg_header = ChunkRandomnessDkgInfoHeader::from_prev_dkg_info_and_body(
                &last_block_dkg_info,
                last_block_dkg_phase,
                &dkg_body,
                &prev_epoch_pks[seat_ord],
                None,
            )
            .unwrap();

            assert_eq!(dkg_header, ChunkRandomnessDkgInfoHeader::None);

            for body in vec![Some(&dkg_body), None].into_iter() {
                assert_eq!(
                    dkg_header.validate(
                        0, // ShardId doesn't matter for Commit
                        &last_block_dkg_info,
                        last_block_dkg_phase,
                        body,
                        seat_ord,
                        &prev_epoch_pks[seat_ord]
                    ),
                    Ok(())
                );
            }
        }

        assert_eq!(last_block_dkg_info.commitment_infos.len(), PREV_EPOCH_BPS);
        assert_eq!(validated_public_sharess.len(), PREV_EPOCH_BPS);

        let last_block_dkg_phase =
            last_block_dkg_info.compute_phase(100, 89, NEXT_EPOCH_BPS as NumSeats);
        assert_eq!(last_block_dkg_phase, RandomnessDKGPhase::Challenge);

        // Move to aggregate phase, set one of the BPs as challenged
        last_block_dkg_info.commitment_infos[CHALLENGE_BP].as_mut().unwrap().was_challenged = true;

        for aggregate_ord in 0..NEXT_K {
            let mut values_to_aggregate = vec![];

            for shard_id in 0..4 {
                // Until we aggregated all the values, the state should be Aggregate, whether at 91 (before
                // the epoch boundary) or 111 (beyond the epoch boundary)
                let last_block_dkg_phase =
                    last_block_dkg_info.compute_phase(100, 91, NEXT_EPOCH_BPS as NumSeats);
                assert_eq!(
                    last_block_dkg_phase,
                    RandomnessDKGPhase::Aggregate(aggregate_ord as u64)
                );

                let last_block_dkg_phase =
                    last_block_dkg_info.compute_phase(100, 111, NEXT_EPOCH_BPS as NumSeats);
                assert_eq!(
                    last_block_dkg_phase,
                    RandomnessDKGPhase::Aggregate(aggregate_ord as u64)
                );

                let seat_ord = shard_id as usize; // seat_ord doesn't really matter for this test

                let dkg_body = ChunkRandomnessDkgInfoBody::from_prev_dkg_info_and_public_key(
                    &last_block_dkg_info,
                    last_block_dkg_phase,
                    Some(seat_ord),
                    &prev_epoch_pks[seat_ord],
                    &next_epoch_pks,
                );
                // There's no "Aggregate" body
                assert_eq!(dkg_body, ChunkRandomnessDkgInfoBody::None);

                // Create a header based on the new body
                let dkg_header = ChunkRandomnessDkgInfoHeader::from_prev_dkg_info_and_body(
                    &last_block_dkg_info,
                    last_block_dkg_phase,
                    &dkg_body,
                    &prev_epoch_pks[seat_ord],
                    Some(
                        &validated_public_sharess
                            .iter()
                            .enumerate()
                            .filter_map(|(i, x)| {
                                if i != CHALLENGE_BP && i != SKIP_BP && i % 4 == shard_id {
                                    Some(x.clone().compress())
                                } else {
                                    None
                                }
                            })
                            .collect(),
                    ),
                )
                .unwrap();

                match &dkg_header {
                    ChunkRandomnessDkgInfoHeader::Aggregate { ordinal, values } => {
                        assert_eq!(ordinal, &(aggregate_ord as u64));
                        assert!(values.len() > 0);
                        values_to_aggregate.extend(values.clone());
                    }
                    _ => {
                        assert!(false);
                    }
                };

                for body in vec![Some(&dkg_body), None].into_iter() {
                    assert_eq!(
                        dkg_header.validate(
                            shard_id as NumShards,
                            &last_block_dkg_info,
                            last_block_dkg_phase,
                            body,
                            seat_ord,
                            &prev_epoch_pks[seat_ord]
                        ),
                        Ok(())
                    );
                }
            }

            last_block_dkg_info.aggregate(&values_to_aggregate.iter().map(|x| x).collect());
        }

        // Once we aggregated all the values, the state should be Completed, whether at 91 (before
        // the epoch boundary) or 111 (beyond the epoch boundary)
        let last_block_dkg_phase =
            last_block_dkg_info.compute_phase(100, 91, NEXT_EPOCH_BPS as NumSeats);
        assert_eq!(last_block_dkg_phase, RandomnessDKGPhase::Completed);

        let last_block_dkg_phase =
            last_block_dkg_info.compute_phase(100, 111, NEXT_EPOCH_BPS as NumSeats);
        assert_eq!(last_block_dkg_phase, RandomnessDKGPhase::Completed);

        // Make sure that the random epoch built from the shares we aggregated in the DKG block info is equal
        // to the random epoch built from original validated shares
        let random_epoch_direct = RandomEpoch::from_shares(
            Params::new(NEXT_EPOCH_BPS, NEXT_K),
            validated_public_sharess.into_iter().enumerate().filter_map(|(i, x)| {
                if i != SKIP_BP && i != CHALLENGE_BP {
                    Some(x.validated_shares)
                } else {
                    None
                }
            }),
        );

        let random_epoch_aggregated =
            last_block_dkg_info.get_next_random_epoch(NEXT_EPOCH_BPS as NumSeats, true).unwrap();

        assert_eq!(random_epoch_direct, random_epoch_aggregated);
    }
}

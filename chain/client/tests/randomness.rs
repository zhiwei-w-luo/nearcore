#[cfg(test)]
#[cfg(feature = "expensive_tests")]
#[cfg(feature = "adversarial")] // adversarial is used to generate an invalid secret share
mod tests {
    use actix::{Addr, System};
    use near_client::test_utils::setup_mock_all_validators;
    use near_client::{ClientActor, ViewClientActor};
    use near_network::types::NetworkAdversarialMessage;
    use near_network::{NetworkClientMessages, NetworkRequests, NetworkResponses, PeerInfo};
    use near_primitives::block::Block;
    use near_primitives::hash::CryptoHash;
    use near_primitives::test_utils::init_integration_logger;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, RwLock};

    /// Checks that various samples of the random reveals yield the same output for the randomness
    /// beacon
    ///
    /// # Returns
    /// Whether we actually had random reveals, and did sampling (in particular, in the case when
    /// there are exactly 9 reveals returns false, because there's only one sample, and we can't
    /// test that all the samples result in the same randomness beacon output).
    #[must_use]
    fn check_rand_reveal_consistency(prev_block: &Block, block: &Block) -> bool {
        // Validate that different subsets of the public shares give the same result
        let rand_reveal = block.rand_reveal.clone();
        let indexes =
            rand_reveal.iter().enumerate().filter_map(|x| x.1.map(|_| x.0)).collect::<Vec<_>>();

        if indexes.is_empty() {
            return false;
        }

        assert!(
            indexes.len() >= 9,
            "indexes.len() = {} must be greater than or equal to 9\nApprovals: {:?}\nRand reveals: {:?}\n",
            indexes.len(),
            block.header.inner_rest.approvals,
            block.rand_reveal
        );

        for _iter in 0..3 {
            let mut sampled_rand_reveals = vec![None; rand_reveal.len()];
            for ord in rand::seq::index::sample(&mut rand::thread_rng(), indexes.len(), 9).iter() {
                assert!(sampled_rand_reveals[indexes[ord]].is_none());
                sampled_rand_reveals[indexes[ord]] = rand_reveal[indexes[ord]];
                assert!(sampled_rand_reveals[indexes[ord]].is_some());
            }

            let cur = prev_block.get_next_random_value(
                17,
                prev_block.header.inner_lite.epoch_id != block.header.inner_lite.epoch_id,
                &sampled_rand_reveals,
            );

            assert_eq!(cur, block.header.inner_rest.random_value);
        }

        indexes.len() > 9
    }

    /// Runs four epochs of block/chunk production, with two non-intersecting validator sets of
    /// different sizes (4 and 8). During the first two epochs there's no interference, while
    /// during the later two epochs some messages are tampered with.
    ///
    /// The following invariants are checked:
    /// 1. That for every commitment secret shares to the next epoch participants are communicated
    ///    exactly once
    /// 2. That block producers in the same epoch never communicate secret shares to each other.
    /// 3. That without any interference secret shares are never requested (they should be
    ///    communicated in the initial messages). In the second part of the test messages are sent
    ///    missing the secret shares, and it is checked that the secret shares are then requested,
    ///    and later received.
    ///
    /// The following message tampering happens in the second part of the test:
    /// 1. All the chunks with commitments from `test3` are withheld. It is then checked that the
    ///    DKG continues as expected, without the shares from `test3`. The exact way the chunks are
    ///    withheld is by preventing all the `PartialEncodedChunkMessage` and `Block` messages from
    ///    `test3` that contain commitments in the third epoch from being delivered.
    /// 2. The `PartialEncodedChunkMessage` from `test2` to `test9` in the third epoch that would
    ///    otherwise contain the secret shares doesn't contain them. It is then checked that `test9`
    ///    requests the secret share from `test2`, and that `test2` sends it (at the same time it
    ///    is ensured that in no other case any shares are contained in any requests or responses)
    #[test]
    fn dkg_chunk_requests_and_responses() {
        let validator_groups = 2;
        init_integration_logger();
        System::run(move || {
            let connectors: Arc<RwLock<Vec<(Addr<ClientActor>, Addr<ViewClientActor>)>>> =
                Arc::new(RwLock::new(vec![]));

            let first_epoch_account_ids = vec!["test1", "test2", "test3", "test4"];
            let second_epoch_account_ids =
                vec!["test5", "test6", "test7", "test8", "test9", "test10", "test11", "test12"];

            let validators =
                vec![first_epoch_account_ids.clone(), second_epoch_account_ids.clone()];
            let key_pairs = vec![
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
                PeerInfo::random(),
            ];

            let largest_traced_height = Arc::new(RwLock::new(0));
            let epoch_id_to_ord = Arc::new(RwLock::new(HashMap::new()));
            let secret_keys = Arc::new(RwLock::new(HashMap::new()));
            let next_secret_keys = Arc::new(RwLock::new(HashMap::new()));
            // First bool is true if the request was sent, the second if the response was sent
            let test9_test2_communication = Arc::new(RwLock::new((false, false)));
            let banned_test3_blocks = Arc::new(RwLock::new(HashSet::new()));

            let connectors1 = connectors.clone();
            let blocks = Arc::new(RwLock::new(HashMap::new()));

            let sampled_rand_reveals_at_least_once = Arc::new(RwLock::new(false));

            let (_, conn) = setup_mock_all_validators(
                validators.clone(),
                key_pairs.clone(),
                validator_groups,
                true,
                1500,
                false,
                false,
                40,
                true,
                false,
                Arc::new(RwLock::new(move |sender_account_id: String, msg: &NetworkRequests| {
                    match msg {
                        NetworkRequests::BlockRequest { hash, .. } => {
                            // Make sure we never requests blocks from `test3` that were withheld below
                            if banned_test3_blocks.read().unwrap().contains(hash) {
                                assert!(false);
                            }
                        },
                        NetworkRequests::Block { block } => {
                            let mut blocks = blocks.write().unwrap();

                            blocks.insert(block.hash(), block.clone());
                            if block.header.inner_lite.height > 1 {
                                if check_rand_reveal_consistency(&blocks.get(&block.header.prev_hash).unwrap(), block) {
                                    *sampled_rand_reveals_at_least_once.write().unwrap() = true;
                                }
                            }

                            let mut epoch_id_to_ord = epoch_id_to_ord.write().unwrap();
                            let epoch_id = block.header.inner_lite.epoch_id.clone();

                            // We check >= 2 instead of == 3 because if the block by test3 happens to
                            // be the very first block, the `epoch_id_to_ord` would not reflect the 
                            // epoch increase yet. test3 is not producing blocks in epochs 2 and 4, so
                            // it's safe to use this check
                            if epoch_id_to_ord.len() >= 2 {
                                // Prevent `test3` from committing
                                if sender_account_id == "test3".to_string() && block.chunks.iter().any(|chunk| chunk.inner.shard_dkg_info_header.is_commit()) {
                                    banned_test3_blocks.write().unwrap().insert(block.hash());
                                    return (NetworkResponses::NoResponse, false);
                                }
                            }

                            // For some invariants in this test it is important that each block
                            // includes all the chunks (specifically, otherwise one might create two
                            // chunks with a secret share for the same recipient)
                            // 90-95 are skipped because this is where we tamper with the messages
                            // from test3, and their chunk is not included
                            if block.header.inner_lite.height > 1 && (block.header.inner_lite.height < 90 || block.header.inner_lite.height > 95) {
                                assert!(block.chunks.iter().all(|chunk| chunk.height_included == block.header.inner_lite.height),
                                        "{:?}",
                                        block.chunks.iter().map(|x| x.height_included).collect::<Vec<_>>());
                            }

                            let next_epoch_ord = epoch_id_to_ord.len();
                            if !epoch_id_to_ord.contains_key(&epoch_id) {
                                let mut next_secret_keys = next_secret_keys.write().unwrap();

                                epoch_id_to_ord.insert(epoch_id.clone(), next_epoch_ord);

                                // On the epoch switch we expect the DKG info to reset
                                assert_eq!(block.dkg_info.commitment_infos.len(), 0);
                                assert_eq!(
                                    block.dkg_info.next_epoch_aggregated_shares.len(),
                                    0
                                );

                                // On each epoch after first we expect exactly 9 shares
                                // (`num_total_parts` in `KeyValueRuntime` with four shards is 17,
                                //  floor(17 / 2) + 1 = 9)
                                if epoch_id.0 != CryptoHash::default() {
                                    assert_eq!(block.dkg_info.this_epoch_shares.len(), 9);
                                }

                                // Make sure that each secret share was indeed communicated
                                // If the first two epochs and the fourth epoch we expect either
                                //   four block producers to send shares to 8, or 8 to 4, resulting
                                //   in 32 shares sent either way. In the third epoch `test3` isn't
                                //   producing a commit, and test2 doesn't send their initial share
                                //   to test9, and thus only 23 secret shares are expected
                                if epoch_id_to_ord.len() > 1 {
                                    if epoch_id_to_ord.len() != 4 {
                                        assert_eq!(secret_keys.read().unwrap().len(), 32, "{:?}", secret_keys);
                                    } else {
                                        assert_eq!(secret_keys.read().unwrap().len(), 23, "{:?}", secret_keys);
                                    }
                                }

                                *secret_keys.write().unwrap() = next_secret_keys.clone();
                                next_secret_keys.clear();

                                if epoch_id_to_ord.len() == 2 {
                                    // Make test7 create an invalid secret share in the second epoch
                                    println!("About to make test7 to produce an invalid commitment");
                                    connectors1.write().unwrap()[6]
                                        .0
                                        .do_send(NetworkClientMessages::Adversarial(NetworkAdversarialMessage::AdvCreateInvalidDKGCommit));
                                }
                            }

                            if epoch_id_to_ord.len() == 4 {
                                // Make sure during the third epoch test9 requested the secret share,
                                // and test2 sent it
                                assert_eq!(*test9_test2_communication.read().unwrap(), (true, true));
                            }

                            if epoch_id_to_ord.len() == 5 {
                                assert!(*sampled_rand_reveals_at_least_once.read().unwrap());
                                System::current().stop();
                            }
                        }
                        NetworkRequests::PartialEncodedChunkMessage {
                            account_id: receiver_account_id,
                            partial_encoded_chunk,
                        } => {
                            if epoch_id_to_ord.read().unwrap().len() >= 2 && epoch_id_to_ord.read().unwrap().len() <= 3 {
                                // Prevent `test3` from committing
                                if sender_account_id == "test3".to_string() && partial_encoded_chunk.header.as_ref().unwrap().inner.shard_dkg_info_header.is_commit() {
                                    return (NetworkResponses::NoResponse, false);
                                };

                                // Do not send the DKG shares from test2 to test9
                                if sender_account_id == "test2".to_string() && receiver_account_id == &"test9".to_string() && !partial_encoded_chunk.dkg_shares.is_empty() {
                                    let mut partial_encoded_chunk = partial_encoded_chunk.clone();
                                    partial_encoded_chunk.dkg_shares = vec![];

                                    connectors1.write().unwrap()[8].0.do_send(NetworkClientMessages::PartialEncodedChunk ( partial_encoded_chunk ));
                                    return (NetworkResponses::NoResponse, false);
                                }
                            }

                            let receiver_account_id = receiver_account_id.clone();
                            let height = partial_encoded_chunk
                                .header
                                .as_ref()
                                .unwrap()
                                .inner
                                .height_created;
                            let mut largest_traced_height =
                                largest_traced_height.write().unwrap();
                            if height > *largest_traced_height {
                                println!(
                                    "FIRST PARTIAL CHUNK FOR HEIGHT {} => {:?}",
                                    height,
                                    partial_encoded_chunk
                                        .header
                                        .as_ref()
                                        .unwrap()
                                        .inner
                                        .shard_dkg_info_header
                                );
                                *largest_traced_height = height;
                            }

                            let mut next_secret_keys = next_secret_keys.write().unwrap();
                            let mut secret_keys = secret_keys.write().unwrap();
                            let secret_key_exists = secret_keys.contains_key(&(
                                sender_account_id.clone(),
                                receiver_account_id.clone(),
                            ));

                            let receiver_in_first_epoch = first_epoch_account_ids
                                .iter()
                                .any(|x| &x.to_string() == &receiver_account_id);
                            let sender_in_first_epoch = first_epoch_account_ids
                                .iter()
                                .any(|x| &x.to_string() == &sender_account_id);

                            /*println!(
                                "{} != {} (prev_block: {})\n{:?}",
                                sender_account_id,
                                receiver_account_id,
                                partial_encoded_chunk.header.as_ref().unwrap().inner.prev_block_hash,
                                partial_encoded_chunk,
                            );*/
                            if receiver_in_first_epoch == sender_in_first_epoch {
                                // Within-epoch messages should always contain parts
                                assert!(partial_encoded_chunk.parts.len() > 0);

                                // If the sender and the receiver are in the same epoch, there
                                // should be no shares exchange
                                assert_eq!(
                                    partial_encoded_chunk.dkg_shares.len(),
                                    0
                                );
                                assert!(!secret_key_exists);
                            } else {
                                // Cross-epoch messages should never contain parts
                                assert_eq!(partial_encoded_chunk.parts.len(), 0);

                                // If the sender and the receiver are in two different epochs,
                                // the secret share should be transmitted exactly once
                                if secret_key_exists
                                    != (partial_encoded_chunk.dkg_shares.len()
                                        == 0)
                                {
                                    println!(
                                        "FAILURE: secret key already exists: {} (height: {}), shares: {:?}",
                                        secret_key_exists,
                                        partial_encoded_chunk.header.as_ref().unwrap().inner.height_created,
                                        partial_encoded_chunk.dkg_shares
                                    );
                                    assert!(false);
                                }

                                if let Some(x) =
                                    partial_encoded_chunk.dkg_shares.first()
                                {
                                    if sender_in_first_epoch == (epoch_id_to_ord.read().unwrap().len() % 2 == 1) {
                                        secret_keys.insert(
                                            (sender_account_id, receiver_account_id),
                                            x.clone(),
                                        );
                                    } else {
                                        next_secret_keys.insert(
                                            (sender_account_id, receiver_account_id),
                                            x.clone(),
                                        );
                                    }
                                }
                            }
                        }
                        NetworkRequests::PartialEncodedChunkRequest { account_id: receiver_account_id, request } => {
                            if epoch_id_to_ord.read().unwrap().len() == 3 && sender_account_id == "test9".to_string() && receiver_account_id == &"test2".to_string() && !request.dkg_part_ords.is_empty() {
                                // The request should be exclusively for the secret shares
                                // (it is important that test2 and test9 do not validate the same shard, otherwise
                                //  test9 would naturally request some parts to reconstruct the whole chunk)
                                assert_eq!(request.part_ords, Vec::<u64>::new());
                                // Today we always request all the receipts whenever we send a request,
                                // and the following assert would trigger
                                // assert_eq!(request.tracking_shards, HashSet::default());

                                println!("REQUESTING SHARES from test2 {}", request.chunk_hash.0);
                                let mut test9_test2_communication = test9_test2_communication.write().unwrap();
                                test9_test2_communication.0 = true;
                            } else {
                                // Without tampering with messages, all the dkg shares should have
                                // arrived in the initial messages
                                assert_eq!(request.dkg_part_ords.len(), 0, "from: {}, to: {}\nrequest: {:?}", sender_account_id, receiver_account_id, request);
                            }
                        }
                        NetworkRequests::PartialEncodedChunkResponse {
                            partial_encoded_chunk,
                            ..
                        } => {
                            // It is harder to know the recipient of the response, but for as long as
                            // there was only one, one can be reasonably certain it is from test9 to
                            // test2
                            if epoch_id_to_ord.read().unwrap().len() == 3 && sender_account_id == "test2".to_string() && !partial_encoded_chunk.dkg_shares.is_empty() {
                                let mut test9_test2_communication = test9_test2_communication.write().unwrap();
                                assert!(partial_encoded_chunk.dkg_shares.len() > 0);
                                test9_test2_communication.1 = true;
                                println!("RESPONDING WITH SHARES from test2 {}", partial_encoded_chunk.chunk_hash.0);
                            } else {
                                // Without tampering with messages, all the dkg shares should have
                                // arrived in the initial messages
                                assert_eq!(
                                    partial_encoded_chunk.dkg_shares.len(),
                                    0
                                );
                            }
                        }
                        _ => {}
                    };
                    (NetworkResponses::NoResponse, true)
                })),
            );
            *connectors.write().unwrap() = conn;

            near_network::test_utils::wait_or_panic(550000);
        })
        .unwrap();
    }

    // MOO test with forkfulness
    // Maintain a hash => know secrets, since secrets can now repeat
}

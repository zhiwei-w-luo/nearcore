extern crate log;

use std::collections::vec_deque::VecDeque;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use actix::Recipient;
use log::{debug, error};
use rand::Rng;

use near_chain::types::validate_chunk_proofs;
use near_chain::{
    byzantine_assert, collect_receipts, ChainStore, ChainStoreAccess, ErrorKind, RuntimeAdapter,
    ValidTransaction,
};
use near_crypto::Signer;
use near_network::types::{
    ChunkOnePartRequestMsg, ChunkPartMsg, ChunkPartRequestMsg, PartialEncodedChunkRequestMsg,
    PeerId,
};
use near_network::NetworkRequests;
use near_pool::TransactionPool;
use near_primitives::hash::CryptoHash;
use near_primitives::merkle::{merklize, verify_path, MerklePath};
use near_primitives::receipt::Receipt;
use near_primitives::sharding::{
    ChunkHash, ChunkOnePart, EncodedShardChunk, PartialEncodedChunk, PartialEncodedChunkPart,
    ReceiptProof, ShardChunkHeader, ShardChunkHeaderInner, ShardProof,
};
use near_primitives::transaction::SignedTransaction;
use near_primitives::types::{
    AccountId, Balance, BlockIndex, EpochId, Gas, MerkleHash, ShardId, StateRoot, ValidatorStake,
};

use crate::chunk_cache::{EncodedChunksCache, EncodedChunksCacheEntry};
pub use crate::types::Error;

mod chunk_cache;
mod types;

const MAX_CHUNK_REQUESTS_TO_KEEP_PER_SHARD: usize = 128;
const CHUNK_REQUEST_RETRY_MS: u64 = 100;
const CHUNK_REQUEST_SWITCH_TO_FULL_FETCH_MS: u64 = 2000;
const CHUNK_REQUEST_RETRY_MAX_MS: u64 = 100_000;

/// Adapter to break dependency of sub-components on the network requests.
/// For tests use MockNetworkAdapter that accumulates the requests to network.
pub trait NetworkAdapter: Sync + Send {
    fn send(&self, msg: NetworkRequests);
}

pub struct NetworkRecipient {
    network_recipient: Recipient<NetworkRequests>,
}

unsafe impl Sync for NetworkRecipient {}

impl NetworkRecipient {
    pub fn new(network_recipient: Recipient<NetworkRequests>) -> Self {
        Self { network_recipient }
    }
}

impl NetworkAdapter for NetworkRecipient {
    fn send(&self, msg: NetworkRequests) {
        let _ = self.network_recipient.do_send(msg);
    }
}

#[derive(PartialEq, Eq)]
pub enum ChunkStatus {
    Complete(Vec<MerklePath>),
    Incomplete,
    Invalid,
}

pub enum ProcessChunkOnePartResult {
    Known,
    HaveAllPartsAndReceipts,
    NeedMoreOnePartsOrReceipts,
}

#[derive(Clone)]
struct ChunkRequestInfo {
    height: BlockIndex,
    parent_hash: CryptoHash,
    shard_id: ShardId,
    added: Instant,
    last_requested: Instant,
}

struct RequestPool {
    retry_duration: Duration,
    switch_to_full_fetch_duration: Duration,
    max_duration: Duration,
    requests: HashMap<ChunkHash, ChunkRequestInfo>,
}

impl RequestPool {
    pub fn new(
        retry_duration: Duration,
        switch_to_full_fetch_duration: Duration,
        max_duration: Duration,
    ) -> Self {
        Self {
            retry_duration,
            switch_to_full_fetch_duration,
            max_duration,
            requests: HashMap::default(),
        }
    }
    pub fn contains_key(&self, chunk_hash: &ChunkHash) -> bool {
        self.requests.contains_key(chunk_hash)
    }

    pub fn insert(&mut self, chunk_hash: ChunkHash, chunk_request: ChunkRequestInfo) {
        self.requests.insert(chunk_hash, chunk_request);
    }

    pub fn remove(&mut self, chunk_hash: &ChunkHash) {
        let _ = self.requests.remove(chunk_hash);
    }

    pub fn fetch(&mut self) -> Vec<(ChunkHash, ChunkRequestInfo)> {
        let mut removed_requests = HashSet::<ChunkHash>::default();
        let mut requests = Vec::new();
        for (chunk_hash, mut chunk_request) in self.requests.iter_mut() {
            if chunk_request.added.elapsed() > self.max_duration {
                debug!(target: "chunks", "Evicted chunk requested that was never fetched {} (shard_id: {})", chunk_hash.0, chunk_request.shard_id);
                removed_requests.insert(chunk_hash.clone());
                continue;
            }
            if chunk_request.last_requested.elapsed() > self.retry_duration {
                chunk_request.last_requested = Instant::now();
                requests.push((chunk_hash.clone(), chunk_request.clone()));
            }
        }
        for chunk_hash in removed_requests {
            self.requests.remove(&chunk_hash);
        }
        requests
    }
}

pub struct ShardsManager {
    me: Option<AccountId>,

    tx_pools: HashMap<ShardId, TransactionPool>,

    runtime_adapter: Arc<dyn RuntimeAdapter>,
    network_adapter: Arc<dyn NetworkAdapter>,

    encoded_chunks: EncodedChunksCache,
    block_hash_to_chunk_headers: HashMap<CryptoHash, Vec<(ShardId, ShardChunkHeader)>>,

    requested_partial_encoded_chunks: RequestPool,

    requests_fifo: VecDeque<(ShardId, ChunkHash, PeerId, u64)>,
    requests: HashMap<(ShardId, ChunkHash, u64), HashSet<(PeerId)>>,
}

impl ShardsManager {
    pub fn new(
        me: Option<AccountId>,
        runtime_adapter: Arc<dyn RuntimeAdapter>,
        network_adapter: Arc<dyn NetworkAdapter>,
    ) -> Self {
        Self {
            me,
            tx_pools: HashMap::new(),
            runtime_adapter,
            network_adapter,
            encoded_chunks: EncodedChunksCache::new(),
            block_hash_to_chunk_headers: HashMap::new(),
            requested_partial_encoded_chunks: RequestPool::new(
                Duration::from_millis(CHUNK_REQUEST_RETRY_MS),
                Duration::from_millis(CHUNK_REQUEST_SWITCH_TO_FULL_FETCH_MS),
                Duration::from_millis(CHUNK_REQUEST_RETRY_MAX_MS),
            ),
            requests_fifo: VecDeque::new(),
            requests: HashMap::new(),
        }
    }

    pub fn prepare_transactions(
        &mut self,
        shard_id: ShardId,
        expected_weight: u32,
    ) -> Result<Vec<SignedTransaction>, Error> {
        if let Some(tx_pool) = self.tx_pools.get_mut(&shard_id) {
            tx_pool.prepare_transactions(expected_weight).map_err(|err| err.into())
        } else {
            Ok(vec![])
        }
    }

    pub fn cares_about_shard_this_or_next_epoch(
        &self,
        account_id: Option<&AccountId>,
        parent_hash: &CryptoHash,
        shard_id: ShardId,
        is_me: bool,
    ) -> bool {
        self.runtime_adapter.cares_about_shard(account_id.clone(), parent_hash, shard_id, is_me)
            || self.runtime_adapter.will_care_about_shard(account_id, parent_hash, shard_id, is_me)
    }

    fn request_partial_encoded_chunk(
        &mut self,
        height: BlockIndex,
        parent_hash: &CryptoHash,
        shard_id: ShardId,
        chunk_hash: &ChunkHash,
        force_request_full: bool,
    ) -> Result<(), Error> {
        let mut bp_to_parts = HashMap::new();

        let cache_entry = match self.encoded_chunks.get(chunk_hash) {
            Some(entry) => entry,
            None => {
                return Ok(());
            }
        };

        let request_full = force_request_full
            || self.cares_about_shard_this_or_next_epoch(
                self.me.as_ref(),
                &parent_hash,
                shard_id,
                true,
            );

        let chunk_producer_account_id = &self.runtime_adapter.get_chunk_producer(
            &self.runtime_adapter.get_epoch_id_from_prev_block(parent_hash)?,
            height,
            shard_id,
        )?;

        for part_ord in 0..self.runtime_adapter.num_total_parts(parent_hash) {
            let part_ord = part_ord as u64;
            if cache_entry.parts.contains_key(&part_ord) {
                continue;
            }

            let need_to_fetch_part = if request_full {
                true
            } else {
                if let Some(me) = &self.me {
                    &self.runtime_adapter.get_part_owner(&parent_hash, part_ord)? == me
                } else {
                    false
                }
            };

            if need_to_fetch_part {
                let fetch_from = self.runtime_adapter.get_part_owner(&parent_hash, part_ord)?;
                let fetch_from = if Some(&fetch_from) == self.me.as_ref() {
                    // If missing own part, request it from the chunk producer
                    chunk_producer_account_id.clone()
                } else {
                    fetch_from
                };

                bp_to_parts.entry(fetch_from).or_insert_with(|| vec![]).push(part_ord);
            }
        }

        let shards_to_fetch_receipts =
        // TODO: only keep shards for which we don't have receipts yet
            if request_full { HashSet::new() } else { self.get_tracking_shards(&parent_hash) };

        // The loop below will be sending PartialEncodedChunkRequestMsg to various block producers.
        // We need to send such a message to the original chunk producer if we do not have the receipts
        //     for some subset of shards, even if we don't need to request any parts from the original
        //     chunk producer.
        if !shards_to_fetch_receipts.is_empty() {
            bp_to_parts.entry(chunk_producer_account_id.clone()).or_insert_with(|| vec![]);
        }

        for (account_id, part_ords) in bp_to_parts {
            let request = PartialEncodedChunkRequestMsg {
                shard_id,
                chunk_hash: chunk_hash.clone(),
                height,
                part_ords,
                tracking_shards: if &account_id == chunk_producer_account_id {
                    shards_to_fetch_receipts.clone()
                } else {
                    HashSet::new()
                },
            };

            self.network_adapter.send(NetworkRequests::PartialEncodedChunkRequest {
                account_id: account_id.clone(),
                request,
            });
        }

        Ok(())
    }

    fn request_chunk_parts(
        &mut self,
        height: BlockIndex,
        parent_hash: &CryptoHash,
        shard_id: ShardId,
        chunk_hash: &ChunkHash,
    ) -> Result<(), Error> {
        /*
        let encoded_chunk = self
            .encoded_chunks
            .get(chunk_hash)
            .expect("request_chunk_parts only should be called if encoded_chunk is present");
        for part_id in 0..self.runtime_adapter.num_total_parts(&parent_hash) {
            // If we already have the part, don't request it again.
            if encoded_chunk.content.parts[part_id].is_some() {
                continue;
            }
            let part_id = part_id as u64;
            let to_whom = self.runtime_adapter.get_part_owner(&parent_hash, part_id)?;
            let to_whom = if Some(&to_whom) == self.me.as_ref() {
                // If missing own part, request it from the chunk producer
                let ret = self.runtime_adapter.get_chunk_producer(
                    &self.runtime_adapter.get_epoch_id_from_prev_block(parent_hash)?,
                    height,
                    shard_id,
                )?;
                ret
            } else {
                to_whom
            };
            assert_ne!(Some(&to_whom), self.me.as_ref());
            self.network_adapter.send(NetworkRequests::ChunkPartRequest {
                account_id: to_whom,
                part_request: ChunkPartRequestMsg {
                    shard_id,
                    chunk_hash: chunk_hash.clone(),
                    height,
                    part_id,
                },
            });
        }*/
        Ok(())
    }

    fn get_tracking_shards(&self, parent_hash: &CryptoHash) -> HashSet<ShardId> {
        (0..self.runtime_adapter.num_shards())
            .filter(|chunk_shard_id| {
                self.cares_about_shard_this_or_next_epoch(
                    self.me.as_ref(),
                    &parent_hash,
                    *chunk_shard_id,
                    true,
                )
            })
            .collect::<HashSet<_>>()
    }

    pub fn request_chunks(
        &mut self,
        chunks_to_request: Vec<ShardChunkHeader>,
    ) -> Result<(), Error> {
        for chunk_header in chunks_to_request {
            let ShardChunkHeader {
                inner:
                    ShardChunkHeaderInner {
                        shard_id,
                        prev_block_hash: parent_hash,
                        height_created: height,
                        ..
                    },
                ..
            } = chunk_header;
            let chunk_hash = chunk_header.chunk_hash();

            if self.requested_partial_encoded_chunks.contains_key(&chunk_hash) {
                continue;
            }

            self.requested_partial_encoded_chunks.insert(
                chunk_hash.clone(),
                ChunkRequestInfo {
                    height,
                    parent_hash,
                    shard_id,
                    last_requested: Instant::now(),
                    added: Instant::now(),
                },
            );
            self.request_partial_encoded_chunk(height, &parent_hash, shard_id, &chunk_hash, false)?;
        }
        Ok(())
    }

    /// Resends chunk requests if haven't received it within expected time.
    pub fn resend_chunk_requests(&mut self) -> Result<(), Error> {
        // Process chunk one part requests.
        let requests = self.requested_partial_encoded_chunks.fetch();
        for (chunk_hash, chunk_request) in requests {
            match self.request_partial_encoded_chunk(
                chunk_request.height,
                &chunk_request.parent_hash,
                chunk_request.shard_id,
                &chunk_hash,
                chunk_request.added.elapsed()
                    > self.requested_partial_encoded_chunks.switch_to_full_fetch_duration,
            ) {
                Ok(()) => {}
                Err(err) => {
                    error!(target: "client", "Error during requesting partial encoded chunk: {}", err);
                }
            }
        }
        Ok(())
    }

    pub fn prepare_chunks(
        &mut self,
        prev_block_hash: CryptoHash,
    ) -> Vec<(ShardId, ShardChunkHeader)> {
        self.block_hash_to_chunk_headers.remove(&prev_block_hash).unwrap_or_else(|| vec![])
    }

    pub fn insert_transaction(&mut self, shard_id: ShardId, tx: ValidTransaction) {
        self.tx_pools
            .entry(shard_id)
            .or_insert_with(TransactionPool::default)
            .insert_transaction(tx);
    }

    pub fn remove_transactions(
        &mut self,
        shard_id: ShardId,
        transactions: &Vec<SignedTransaction>,
    ) {
        if let Some(pool) = self.tx_pools.get_mut(&shard_id) {
            pool.remove_transactions(transactions)
        }
    }

    pub fn reintroduce_transactions(
        &mut self,
        shard_id: ShardId,
        transactions: &Vec<SignedTransaction>,
    ) {
        self.tx_pools
            .entry(shard_id)
            .or_insert_with(TransactionPool::default)
            .reintroduce_transactions(transactions);
    }

    pub fn process_chunk_part_request(
        &mut self,
        request: ChunkPartRequestMsg,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        /*
        let mut served = false;
        if let Some(chunk) = self.encoded_chunks.get(&request.chunk_hash) {
            if request.part_id as usize >= chunk.content.parts.len() {
                return Err(Error::InvalidChunkPartId);
            }

            if chunk.content.parts[request.part_id as usize].is_some() {
                served = true;
                self.network_adapter.send(NetworkRequests::ChunkPart {
                    peer_id: peer_id.clone(),
                    part: chunk.create_chunk_part_msg(
                        request.part_id,
                        // Part should never exist in the chunk content if the merkle path for it is
                        //    not in merkle_paths, so `unwrap` here
                        self.merkle_paths
                            .get(&(request.chunk_hash.clone(), request.part_id))
                            .unwrap()
                            .clone(),
                    ),
                });
            }
        }
        if !served {
            debug!(
                "part request for {}:{}, I'm {:?}, served: {}",
                request.chunk_hash.0, request.part_id, self.me, served
            );
        }
        if !served {
            while self.requests_fifo.len() + 1 > MAX_CHUNK_REQUESTS_TO_KEEP_PER_SHARD {
                let (r_shard_id, r_hash, r_peer, r_part_id) =
                    self.requests_fifo.pop_front().unwrap();
                self.requests.entry((r_shard_id, r_hash.clone(), r_part_id)).and_modify(|v| {
                    let _ = v.remove(&r_peer);
                });
                if self
                    .requests
                    .get(&(r_shard_id, r_hash.clone(), r_part_id))
                    .map_or_else(|| false, |x| x.is_empty())
                {
                    self.requests.remove(&(r_shard_id, r_hash, r_part_id));
                }
            }
            if self
                .requests
                .entry((request.shard_id, request.chunk_hash.clone(), request.part_id))
                .or_insert_with(HashSet::default)
                .insert(peer_id.clone())
            {
                self.requests_fifo.push_back((
                    request.shard_id,
                    request.chunk_hash,
                    peer_id,
                    request.part_id,
                ));
            }
        }*/

        Ok(())
    }

    fn receipts_recipient_filter(
        &self,
        from_shard_id: ShardId,
        tracking_shards: &HashSet<ShardId>,
        receipts: &Vec<Receipt>,
        proofs: &Vec<MerklePath>,
    ) -> Vec<ReceiptProof> {
        let mut one_part_receipt_proofs = vec![];
        for to_shard_id in 0..self.runtime_adapter.num_shards() {
            if tracking_shards.contains(&to_shard_id) {
                one_part_receipt_proofs.push(ReceiptProof(
                    receipts
                        .iter()
                        .filter(|&receipt| {
                            self.runtime_adapter.account_id_to_shard_id(&receipt.receiver_id)
                                == to_shard_id
                        })
                        .cloned()
                        .collect(),
                    ShardProof {
                        from_shard_id,
                        to_shard_id,
                        proof: proofs[to_shard_id as usize].clone(),
                    },
                ))
            }
        }
        one_part_receipt_proofs
    }

    pub fn process_chunk_one_part_request(
        &mut self,
        request: ChunkOnePartRequestMsg,
        peer_id: PeerId,
        chain_store: &mut ChainStore,
    ) -> Result<(), Error> {
        /*
        debug!(target:"chunks", "Received one part request for {:?}, I'm {:?}", request.chunk_hash.0, self.me);
        if let Some(encoded_chunk) = self.encoded_chunks.get(&request.chunk_hash) {
            if request.part_id as usize >= encoded_chunk.content.parts.len() {
                return Err(Error::InvalidChunkPartId);
            }

            // TODO: should have a ref to ChainStore instead, and use the cache
            if let Ok(chunk) = chain_store.get_chunk(&request.chunk_hash) {
                let receipts_hashes =
                    self.runtime_adapter.build_receipts_hashes(&chunk.receipts)?;
                let (receipts_root, receipts_proofs) = merklize(&receipts_hashes);
                let one_part_receipt_proofs = self.receipts_recipient_filter(
                    request.shard_id,
                    &request.tracking_shards,
                    &chunk.receipts,
                    &receipts_proofs,
                );

                assert_eq!(chunk.header.inner.outgoing_receipts_root, receipts_root);
                debug!(target: "chunks",
                    "Responding to one part request for {:?}, I'm {:?}",
                    request.chunk_hash.0, self.me
                );
                self.network_adapter.send(NetworkRequests::ChunkOnePartResponse {
                    peer_id,
                    header_and_part: encoded_chunk.create_chunk_one_part(
                        request.part_id,
                        one_part_receipt_proofs,
                        // It should be impossible to have a part but not the merkle path
                        self.merkle_paths
                            .get(&(request.chunk_hash.clone(), request.part_id))
                            .unwrap()
                            .clone(),
                    ),
                });
            }
        }*/

        Ok(())
    }

    pub fn check_chunk_complete(
        data_parts: usize,
        total_parts: usize,
        chunk: &mut EncodedShardChunk,
    ) -> ChunkStatus {
        let parity_parts = total_parts - data_parts;
        if chunk.content.num_fetched_parts() >= data_parts {
            chunk.content.reconstruct(data_parts, parity_parts);

            let (merkle_root, paths) = chunk.content.get_merkle_hash_and_paths();
            if merkle_root == chunk.header.inner.encoded_merkle_root {
                ChunkStatus::Complete(paths)
            } else {
                ChunkStatus::Invalid
            }
        } else {
            ChunkStatus::Incomplete
        }
    }

    /// Add a part to current encoded chunk stored in memory. It's present only if One Part was present and signed correctly.
    fn validate_part(
        &mut self,
        merkle_root: MerkleHash,
        part: &PartialEncodedChunkPart,
        num_total_parts: usize,
    ) -> Result<(), Error> {
        if (part.part_ord as usize) < num_total_parts {
            // We have the chunk but haven't seen the part, so actually need to process it
            // First validate the merkle proof
            if !verify_path(merkle_root, &part.merkle_proof, &part.part) {
                return Err(Error::InvalidMerkleProof);
            }

            Ok(())
        } else {
            Err(Error::InvalidChunkPartId)
        }
    }

    pub fn persist_chunk_if_complete(
        &mut self,
        chunk_hash: &ChunkHash,
        prev_block_hash: &CryptoHash,
        chain_store: &mut ChainStore,
    ) -> Result<Option<CryptoHash>, Error> {
        /*
        let chunk = self.encoded_chunks.get_mut(chunk_hash).unwrap();
        match ShardsManager::check_chunk_complete(
            self.runtime_adapter.num_data_parts(&prev_block_hash),
            self.runtime_adapter.num_total_parts(&prev_block_hash),
            chunk,
        ) {
            ChunkStatus::Complete(merkle_paths) => {
                let chunk = self
                    .encoded_chunks
                    .get(&chunk_hash)
                    .map(std::clone::Clone::clone)
                    .expect("Present if add_part returns Ok");
                self.process_encoded_chunk(&chunk, merkle_paths, chain_store)
            }
            ChunkStatus::Incomplete => Ok(None),
            ChunkStatus::Invalid => {
                let chunk =
                    self.encoded_chunks.get(&chunk_hash).expect("Present if add_part returns Ok");
                for i in
                    0..self.runtime_adapter.num_total_parts(&chunk.header.inner.prev_block_hash)
                {
                    self.merkle_paths.remove(&(chunk_hash.clone(), i as u64));
                }
                self.encoded_chunks.remove(&chunk_hash);
                Ok(None)
            }
        }*/

        Ok(None)
    }

    /// Returns the hash of the enclosing block if a chunk part was not known previously, and the chunk is complete after receiving it
    /// Once it receives the last part necessary to reconstruct, the chunk gets reconstructed and fills in all the remaining parts,
    ///     thus once the remaining parts arrive, they do not trigger returning the hash again.
    pub fn process_chunk_part(
        &mut self,
        part: ChunkPartMsg,
        chain_store: &mut ChainStore,
    ) -> Result<Option<CryptoHash>, Error> {
        /*
        let part_id = part.part_id;
        let chunk_hash = part.chunk_hash.clone();
        if !self.requested_chunks.contains_key(&chunk_hash) {
            // Received chunk that wasn't requested.
            return Ok(None);
        }
        match self.add_part_to_encoded_chunk(part) {
            Ok(()) => {
                let prev_block_hash = self
                    .encoded_chunks
                    .get_mut(&chunk_hash)
                    .expect("Successfully added part")
                    .header
                    .inner
                    .prev_block_hash;
                self.persist_chunk_if_complete(&chunk_hash, &prev_block_hash, chain_store)
            }
            Err(Error::KnownPart) => Ok(None),
            Err(Error::UnknownChunk) => {
                debug!(target: "shards", "Received part {} for unknown chunk {:?}, declining", part_id, chunk_hash);
                Ok(None)
            }
            Err(err) => Err(err),
        }*/

        Ok(None)
    }

    pub fn process_chunk_one_part(
        &mut self,
        one_part: ChunkOnePart,
        chain_store: &mut ChainStore,
    ) -> Result<ProcessChunkOnePartResult, Error> {
        /*
        let chunk_hash = one_part.chunk_hash.clone();
        let prev_block_hash = one_part.header.inner.prev_block_hash;

        if let Some(ec) = self.encoded_chunks.get(&one_part.chunk_hash) {
            if ec.content.parts[one_part.part_id as usize].is_some() {
                return Ok(ProcessChunkOnePartResult::Known);
            }
        }

        match self.runtime_adapter.get_epoch_id_from_prev_block(&prev_block_hash) {
            Ok(_) => {}
            Err(err) => {
                return Err(err.into());
            }
        }

        if !self.runtime_adapter.verify_chunk_header_signature(&one_part.header)? {
            byzantine_assert!(false);
            return Err(Error::InvalidChunkSignature);
        }

        if one_part.shard_id != one_part.header.inner.shard_id {
            byzantine_assert!(false);
            return Err(Error::InvalidChunkShardId);
        }

        if !verify_path(
            one_part.header.inner.encoded_merkle_root,
            &one_part.merkle_path,
            &one_part.part,
        ) {
            // This is not slashable behvior, because we can't prove that merkle path is the one that validator signed.
            byzantine_assert!(false);
            return Err(Error::InvalidMerkleProof);
        }

        // Checking one_part's receipts validity here
        let receipts = collect_receipts(&one_part.receipt_proofs);
        let receipts_hashes = self.runtime_adapter.build_receipts_hashes(&receipts)?;
        let mut proof_index = 0;
        for shard_id in 0..self.runtime_adapter.num_shards() {
            if self.cares_about_shard_this_or_next_epoch(
                self.me.as_ref(),
                &prev_block_hash,
                shard_id,
                true,
            ) {
                if proof_index == one_part.receipt_proofs.len()
                    || shard_id != (one_part.receipt_proofs[proof_index].1).to_shard_id
                    || !verify_path(
                        one_part.header.inner.outgoing_receipts_root,
                        &(one_part.receipt_proofs[proof_index].1).proof,
                        &receipts_hashes[shard_id as usize],
                    )
                {
                    byzantine_assert!(false);
                    return Err(Error::ChainError(ErrorKind::InvalidReceiptsProof.into()));
                }
                proof_index += 1;
            }
        }
        if proof_index != one_part.receipt_proofs.len() {
            byzantine_assert!(false);
            return Err(Error::ChainError(ErrorKind::InvalidReceiptsProof.into()));
        }

        let total_parts = self.runtime_adapter.num_total_parts(&prev_block_hash);
        self.encoded_chunks.entry(one_part.chunk_hash.clone()).or_insert_with(|| {
            EncodedShardChunk::from_header(one_part.header.clone(), total_parts)
        });

        if let Some(send_to) =
            self.requests.remove(&(one_part.shard_id, chunk_hash.clone(), one_part.part_id))
        {
            for whom in send_to {
                self.network_adapter.send(NetworkRequests::ChunkPart {
                    peer_id: whom,
                    part: ChunkPartMsg {
                        shard_id: one_part.shard_id,
                        chunk_hash: chunk_hash.clone(),
                        part_id: one_part.part_id,
                        part: one_part.part.clone(),
                        merkle_path: one_part.merkle_path.clone(),
                    },
                });
            }
        }

        self.merkle_paths
            .insert((one_part.chunk_hash.clone(), one_part.part_id), one_part.merkle_path.clone());

        self.encoded_chunks.get_mut(&one_part.chunk_hash).unwrap().content.parts
            [one_part.part_id as usize] = Some(one_part.part.clone());

        self.persist_chunk_if_complete(&one_part.chunk_hash, &prev_block_hash, chain_store)?;

        let have_all_one_parts = self.has_all_one_parts(
            &prev_block_hash,
            self.encoded_chunks.get(&one_part.chunk_hash).unwrap(),
        )?;

        if have_all_one_parts {
            let mut store_update = chain_store.store_update();
            store_update.save_chunk_one_part(&chunk_hash, one_part.clone());
            store_update.commit()?;

            self.requested_one_parts.remove(&one_part.chunk_hash);
        }

        // If we do not follow this shard, having the one parts is sufficient to include the chunk in the block
        if have_all_one_parts
            && !self.cares_about_shard_this_or_next_epoch(
                self.me.as_ref(),
                &prev_block_hash,
                one_part.shard_id,
                true,
            )
        {
            self.block_hash_to_chunk_headers
                .entry(one_part.header.inner.prev_block_hash)
                .or_insert_with(|| vec![])
                .push((one_part.shard_id, one_part.header.clone()));
        }

        Ok(if have_all_one_parts {
            ProcessChunkOnePartResult::HaveAllOneParts
        } else {
            ProcessChunkOnePartResult::NeedMoreOneParts
        }) */

        Ok(ProcessChunkOnePartResult::HaveAllPartsAndReceipts)
    }

    fn process_partial_encoded_chunk(
        &mut self,
        partial_encoded_chunk: PartialEncodedChunk,
        chain_store: &mut ChainStore,
    ) -> Result<ProcessChunkOnePartResult, Error> {
        let chunk_hash = partial_encoded_chunk.chunk_hash.clone();

        let header = match &partial_encoded_chunk.header {
            Some(header) => header.clone(),
            None => {
                if let Some(encoded_chunk) = self.encoded_chunks.get(&chunk_hash) {
                    encoded_chunk.header.clone()
                } else {
                    return Err(Error::UnknownChunk);
                }
            }
        };

        if header.chunk_hash() != chunk_hash
            || header.inner.shard_id != partial_encoded_chunk.shard_id
        {
            return Err(Error::InvalidChunkHeader);
        }

        let prev_block_hash = header.inner.prev_block_hash;

        match self.runtime_adapter.get_epoch_id_from_prev_block(&prev_block_hash) {
            Ok(_) => {}
            Err(err) => {
                return Err(err.into());
            }
        }

        // TODO: Check if we don't need it?

        if !self.runtime_adapter.verify_chunk_header_signature(&header)? {
            byzantine_assert!(false);
            return Err(Error::InvalidChunkSignature);
        }

        if partial_encoded_chunk.shard_id != header.inner.shard_id {
            byzantine_assert!(false);
            return Err(Error::InvalidChunkShardId);
        }

        let num_total_parts = self.runtime_adapter.num_total_parts(&prev_block_hash);
        for part_info in partial_encoded_chunk.parts.iter() {
            // TODO: only validate parts we care about
            self.validate_part(header.inner.encoded_merkle_root, part_info, num_total_parts)?;
        }

        // Checking partial_encoded_chunk's receipts validity here
        let receipts = collect_receipts(&partial_encoded_chunk.receipts);
        let receipts_hashes = self.runtime_adapter.build_receipts_hashes(&receipts)?;
        let mut proof_index = 0;

        for proof in partial_encoded_chunk.receipts.iter() {
            let shard_id = proof.1.to_shard_id;
            if self.cares_about_shard_this_or_next_epoch(
                self.me.as_ref(),
                &prev_block_hash,
                shard_id,
                true,
            ) {
                if !verify_path(
                    header.inner.outgoing_receipts_root,
                    &(proof.1).proof,
                    &receipts_hashes[shard_id as usize],
                ) {
                    byzantine_assert!(false);
                    return Err(Error::ChainError(ErrorKind::InvalidReceiptsProof.into()));
                }
            }
        }

        for part_info in partial_encoded_chunk.parts.iter() {
            if let Some(send_to) = self.requests.remove(&(
                partial_encoded_chunk.shard_id,
                chunk_hash.clone(),
                part_info.part_ord,
            )) {
                // TODO: send the partial encoded chunk
                /*                for whom in send_to {
                    self.network_adapter.send(NetworkRequests::ChunkPart {
                        peer_id: whom,
                        part: ChunkPartMsg {
                            shard_id: partial_encoded_chunk.shard_id,
                            chunk_hash: chunk_hash.clone(),
                            part_id: partial_encoded_chunk.part_ord,
                            part: partial_encoded_chunk.part.clone(),
                            merkle_path: partial_encoded_chunk.merkle_path.clone(),
                        },
                    });
                }*/
            }
        }

        // TODO: update the permament storage

        if !self.encoded_chunks.process_partial_encoded_chunk(&partial_encoded_chunk) {
            return Err(Error::ChainError(ErrorKind::InvalidChunkHeight.into()));
        }

        let have_all_parts = self.has_all_parts(
            &prev_block_hash,
            self.encoded_chunks.get(&partial_encoded_chunk.chunk_hash).unwrap(),
        )?;
        let have_all_receipts = self.has_all_receipts(
            &prev_block_hash,
            self.encoded_chunks.get(&partial_encoded_chunk.chunk_hash).unwrap(),
        )?;

        self.requested_partial_encoded_chunks.remove(&chunk_hash);

        if have_all_parts {
            self.block_hash_to_chunk_headers
                .entry(header.inner.prev_block_hash)
                .or_insert_with(|| vec![])
                .push((partial_encoded_chunk.shard_id, header.clone()));
        }

        Ok(if have_all_parts && have_all_receipts {
            ProcessChunkOnePartResult::HaveAllPartsAndReceipts
        } else {
            ProcessChunkOnePartResult::NeedMoreOnePartsOrReceipts
        })
    }

    fn has_all_receipts(
        &self,
        prev_block_hash: &CryptoHash,
        chunk_entry: &EncodedChunksCacheEntry,
    ) -> Result<bool, Error> {
        for shard_id in 0..self.runtime_adapter.num_shards() {
            let shard_id = shard_id as ShardId;
            if !chunk_entry.receipts.contains_key(&shard_id) {
                if self.cares_about_shard_this_or_next_epoch(
                    self.me.as_ref(),
                    &prev_block_hash,
                    shard_id,
                    true,
                ) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn has_all_parts(
        &self,
        prev_block_hash: &CryptoHash,
        chunk_entry: &EncodedChunksCacheEntry,
    ) -> Result<bool, Error> {
        for part_ord in 0..self.runtime_adapter.num_total_parts(&prev_block_hash) {
            let part_ord = part_ord as u64;
            if !chunk_entry.parts.contains_key(&part_ord) {
                if Some(self.runtime_adapter.get_part_owner(&prev_block_hash, part_ord)?) == self.me
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub fn create_encoded_shard_chunk(
        &mut self,
        prev_block_hash: CryptoHash,
        prev_state_root: StateRoot,
        height: u64,
        shard_id: ShardId,
        gas_used: Gas,
        gas_limit: Gas,
        rent_paid: Balance,
        validator_reward: Balance,
        balance_burnt: Balance,
        validator_proposals: Vec<ValidatorStake>,
        transactions: &Vec<SignedTransaction>,
        outgoing_receipts: &Vec<Receipt>,
        outgoing_receipts_root: CryptoHash,
        tx_root: CryptoHash,
        signer: &dyn Signer,
    ) -> Result<(EncodedShardChunk, Vec<MerklePath>), Error> {
        let total_parts = self.runtime_adapter.num_total_parts(&prev_block_hash);
        let data_parts = self.runtime_adapter.num_data_parts(&prev_block_hash);
        EncodedShardChunk::new(
            prev_block_hash,
            prev_state_root,
            height,
            shard_id,
            total_parts,
            data_parts,
            gas_used,
            gas_limit,
            rent_paid,
            validator_reward,
            balance_burnt,
            tx_root,
            validator_proposals,
            transactions,
            outgoing_receipts,
            outgoing_receipts_root,
            signer,
        )
        .map_err(|err| err.into())
    }

    pub fn process_encoded_chunk(
        &mut self,
        chunk: &EncodedShardChunk,
        merkle_paths: Vec<MerklePath>,
        chain_store: &mut ChainStore,
    ) -> Result<Option<CryptoHash>, Error> {
        /*
        let chunk_hash = chunk.header.chunk_hash();
        assert!(self.encoded_chunks.contains_key(&chunk_hash));
        let cares_about_shard = self.cares_about_shard_this_or_next_epoch(
            self.me.as_ref(),
            &chunk.header.inner.prev_block_hash,
            chunk.header.inner.shard_id,
            true,
        );
        let mut store_update = chain_store.store_update();
        if let Ok(shard_chunk) = chunk
            .decode_chunk(self.runtime_adapter.num_data_parts(&chunk.header.inner.prev_block_hash))
            .map_err(|err| Error::from(err))
            .and_then(|shard_chunk| {
                if !validate_chunk_proofs(&shard_chunk, &*self.runtime_adapter)? {
                    return Err(Error::InvalidChunk);
                }
                Ok(shard_chunk)
            })
        {
            debug!(target: "chunks", "Reconstructed and decoded chunk {}, encoded length was {}, num txs: {}, I'm {:?}", chunk_hash.0, chunk.header.inner.encoded_length, shard_chunk.transactions.len(), self.me);

            // Decoded a valid chunk, store it in the permanent store ...
            store_update.save_chunk(&chunk_hash, shard_chunk);
            store_update.commit()?;
            // ... and include into the block if we are the producer
            if cares_about_shard {
                self.block_hash_to_chunk_headers
                    .entry(chunk.header.inner.prev_block_hash)
                    .or_insert_with(|| vec![])
                    .push((chunk.header.inner.shard_id, chunk.header.clone()));
            }

            for (part_id, merkle_path) in merkle_paths.iter().enumerate() {
                let part_id = part_id as u64;
                self.merkle_paths.insert((chunk_hash.clone(), part_id), merkle_path.clone());
            }
            self.requested_chunks.remove(&chunk_hash);

            return Ok(Some(chunk.header.inner.prev_block_hash));
        } else {
            // Can't decode chunk or has invalid proofs, ignore it
            error!(target: "chunks", "Reconstructed but failed to decoded chunk {}", chunk_hash.0);
            // TODO: mark chunk invalid.
            for i in 0..self.runtime_adapter.num_total_parts(&chunk.header.inner.prev_block_hash) {
                self.merkle_paths.remove(&(chunk_hash.clone(), i as u64));
            }
            self.encoded_chunks.remove(&chunk_hash);
            self.requested_chunks.remove(&chunk_hash);
            return Ok(None);
        }
        */

        Ok(None)
    }

    pub fn distribute_encoded_chunk(
        &mut self,
        encoded_chunk: EncodedShardChunk,
        merkle_paths: Vec<MerklePath>,
        outgoing_receipts: Vec<Receipt>,
        chain_store: &mut ChainStore,
    ) {
        // TODO: if the number of validators exceeds the number of parts, this logic must be changed
        let prev_block_hash = encoded_chunk.header.inner.prev_block_hash;
        let chunk_hash = encoded_chunk.chunk_hash();
        let shard_id = encoded_chunk.header.inner.shard_id;
        let outgoing_receipts_hashes =
            self.runtime_adapter.build_receipts_hashes(&outgoing_receipts).unwrap();
        let (outgoing_receipts_root, outgoing_receipts_proofs) =
            merklize(&outgoing_receipts_hashes);
        assert_eq!(encoded_chunk.header.inner.outgoing_receipts_root, outgoing_receipts_root);

        let mut block_producer_mapping = HashMap::new();

        for part_ord in 0..self.runtime_adapter.num_total_parts(&prev_block_hash) {
            let part_ord = part_ord as u64;
            let to_whom = self.runtime_adapter.get_part_owner(&prev_block_hash, part_ord).unwrap();

            let entry = block_producer_mapping.entry(to_whom.clone()).or_insert_with(|| vec![]);
            entry.push(part_ord);
        }

        for (to_whom, part_ords) in block_producer_mapping {
            let tracking_shards = (0..self.runtime_adapter.num_shards())
                .filter(|chunk_shard_id| {
                    self.cares_about_shard_this_or_next_epoch(
                        Some(&to_whom),
                        &prev_block_hash,
                        *chunk_shard_id,
                        false,
                    )
                })
                .collect();

            let one_part_receipt_proofs = self.receipts_recipient_filter(
                shard_id,
                &tracking_shards,
                &outgoing_receipts,
                &outgoing_receipts_proofs,
            );
            let partial_encoded_chunk = encoded_chunk.create_partial_encoded_chunk(
                part_ords,
                true,
                one_part_receipt_proofs,
                &merkle_paths,
            );

            self.network_adapter.send(NetworkRequests::PartialEncodedChunkMessage {
                account_id: to_whom.clone(),
                partial_encoded_chunk,
            });
        }

        // Save this chunk into encoded_chunks & process encoded chunk to add to the store.
        let cache_entry = EncodedChunksCacheEntry {
            header: encoded_chunk.header,
            parts: encoded_chunk
                .content
                .parts
                .into_iter()
                .zip(merkle_paths)
                .enumerate()
                .map(|(part_ord, (part, merkle_proof))| {
                    let part_ord = part_ord as u64;
                    let part = part.unwrap();
                    (part_ord, PartialEncodedChunkPart { part_ord, part, merkle_proof })
                })
                .collect(),
            receipts: self
                .receipts_recipient_filter(
                    shard_id,
                    &(0..self.runtime_adapter.num_shards()).collect(),
                    &outgoing_receipts,
                    &outgoing_receipts_proofs,
                )
                .into_iter()
                .map(|receipt_proof| (receipt_proof.1.to_shard_id, receipt_proof))
                .collect(),
        };

        // TODO: process encoded chunk
        /*self.process_encoded_chunk(
            &encoded_chunk,
            (0..encoded_chunk.content.parts.len())
                .map(|part_id| {
                    self.merkle_paths.get(&(chunk_hash.clone(), part_id as u64)).unwrap().clone()
                })
                .collect(),
            chain_store,
        )
        .expect("Failed to process just created chunk");*/
    }
}

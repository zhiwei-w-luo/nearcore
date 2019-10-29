extern crate log;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use actix::Recipient;
use log::{debug, error};

use near_chain::types::validate_chunk_proofs;
use near_chain::{
    byzantine_assert, collect_receipts, ChainStore, ErrorKind, RuntimeAdapter, ValidTransaction,
};
use near_crypto::Signer;
use near_network::types::{PartialEncodedChunkRequestMsg, PeerId};
use near_network::NetworkRequests;
use near_pool::TransactionPool;
use near_primitives::hash::CryptoHash;
use near_primitives::merkle::{merklize, verify_path, MerklePath};
use near_primitives::receipt::Receipt;
use near_primitives::sharding::{
    ChunkHash, EncodedShardChunk, PartialEncodedChunk, PartialEncodedChunkPart, ReceiptProof,
    ShardChunkHeader, ShardChunkHeaderInner, ShardProof,
};
use near_primitives::transaction::SignedTransaction;
use near_primitives::types::{
    AccountId, Balance, BlockIndex, Gas, MerkleHash, ShardId, StateRoot, ValidatorStake,
};

use crate::chunk_cache::{EncodedChunksCache, EncodedChunksCacheEntry};
pub use crate::types::Error;

mod chunk_cache;
mod types;

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

pub enum ProcessPartialEncodedChunkResult {
    Known,
    // The CryptoHash is the previous block hash (which might be unknown to the caller) to start
    //     unblocking the blocks from
    HaveAllPartsAndReceipts(CryptoHash),
    // The Header is the header of the current chunk, which is unknown to the caller, to request
    //     parts / receipts for
    NeedMoreOnePartsOrReceipts(ShardChunkHeader),
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

    pub fn process_partial_encoded_chunk_request(
        &mut self,
        request: PartialEncodedChunkRequestMsg,
        peer_id: PeerId,
        _chain_store: &mut ChainStore,
    ) {
        debug!(target:"chunks", "Received partial encoded chunk request for {:?}, I'm {:?}", request.chunk_hash.0, self.me);
        if let Some(entry) = self.encoded_chunks.get(&request.chunk_hash) {
            let parts = request
                .part_ords
                .iter()
                .map(|part_ord| entry.parts.get(&part_ord))
                .collect::<Vec<_>>();

            if parts.iter().any(|x| x.is_none()) {
                return;
            }

            let parts = parts.into_iter().map(|x| x.unwrap().clone()).collect::<Vec<_>>();

            let receipts = request
                .tracking_shards
                .iter()
                .map(|shard_id| entry.receipts.get(&shard_id))
                .collect::<Vec<_>>();

            if receipts.iter().any(|x| x.is_none()) {
                return;
            }

            let receipts = receipts.into_iter().map(|x| x.unwrap().clone()).collect::<Vec<_>>();

            let partial_encoded_chunk = PartialEncodedChunk {
                shard_id: entry.header.inner.shard_id,
                chunk_hash: entry.header.chunk_hash(),
                header: None,
                parts,
                receipts,
            };

            self.network_adapter.send(NetworkRequests::PartialEncodedChunkResponse {
                peer_id,
                partial_encoded_chunk,
            });
        }
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

    pub fn process_partial_encoded_chunk(
        &mut self,
        partial_encoded_chunk: PartialEncodedChunk,
        _chain_store: &mut ChainStore,
    ) -> Result<ProcessPartialEncodedChunkResult, Error> {
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

        // TODO: update the permament storage

        if !self.encoded_chunks.process_partial_encoded_chunk(&partial_encoded_chunk) {
            return Err(Error::ChainError(ErrorKind::InvalidChunkHeight.into()));
        }

        let entry = self.encoded_chunks.get(&chunk_hash).unwrap();

        let have_all_parts = self.has_all_parts(&prev_block_hash, entry)?;
        let have_all_receipts = self.has_all_receipts(&prev_block_hash, entry)?;

        let can_reconstruct =
            entry.parts.len() >= self.runtime_adapter.num_data_parts(&prev_block_hash);

        if have_all_parts {
            self.block_hash_to_chunk_headers
                .entry(header.inner.prev_block_hash)
                .or_insert_with(|| vec![])
                .push((partial_encoded_chunk.shard_id, header.clone()));
        }

        if have_all_parts && have_all_receipts {
            let cares_about_shard = self.cares_about_shard_this_or_next_epoch(
                self.me.as_ref(),
                &prev_block_hash,
                header.inner.shard_id,
                true,
            );

            // If all the parts and receipts are received, and we don't care about the shard,
            //    no need to request anything else.
            // If we do care about the shard, we will remove the request once the full chunk is
            //    assembled.
            if !cares_about_shard {
                self.requested_partial_encoded_chunks.remove(&chunk_hash);
                return Ok(ProcessPartialEncodedChunkResult::HaveAllPartsAndReceipts(
                    prev_block_hash,
                ));
            }
        }

        if can_reconstruct {
            //TODO
            //self.process_encoded_chunk(encoded_chunk, chain_store);
            return Ok(ProcessPartialEncodedChunkResult::HaveAllPartsAndReceipts(prev_block_hash));
        }

        Ok(ProcessPartialEncodedChunkResult::NeedMoreOnePartsOrReceipts(header))
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
        _chain_store: &mut ChainStore,
    ) -> Result<Option<CryptoHash>, Error> {
        let chunk_hash = chunk.header.chunk_hash();

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
            self.requested_partial_encoded_chunks.remove(&chunk_hash);

            return Ok(Some(chunk.header.inner.prev_block_hash));
        } else {
            // Can't decode chunk or has invalid proofs, ignore it
            error!(target: "chunks", "Reconstructed but failed to decoded chunk {}", chunk_hash.0);
            // TODO: mark chunk invalid.
            self.encoded_chunks.remove(&chunk_hash);
            self.requested_partial_encoded_chunks.remove(&chunk_hash);
            return Ok(None);
        }
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

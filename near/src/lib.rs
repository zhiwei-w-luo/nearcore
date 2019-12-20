use std::fs;
use std::path::Path;
use std::sync::Arc;

use actix::{Actor, Addr};
use log::info;

use near_client::{ClientActor, ViewClientActor};
use near_jsonrpc::start_http;
use near_network::{NetworkRecipient, PeerManagerActor};
use near_store::create_store;
use near_telemetry::TelemetryActor;

pub use crate::config::{
    init_configs, load_config, load_test_config, GenesisConfig, NearConfig, NEAR_BASE,
};
pub use crate::runtime::NightshadeRuntime;
use near_chain::ChainGenesis;

pub mod config;
mod runtime;
mod shard_tracker;

const STORE_PATH: &str = "data";

pub fn get_store_path(base_path: &Path) -> String {
    let mut store_path = base_path.to_owned();
    store_path.push(STORE_PATH);
    match fs::canonicalize(store_path.clone()) {
        Ok(path) => info!(target: "near", "Opening store database at {:?}", path),
        _ => {
            info!(target: "near", "Did not find {:?} path, will be creating new store database", store_path)
        }
    };
    store_path.to_str().unwrap().to_owned()
}

pub fn get_default_home() -> String {
    match std::env::var("NEAR_HOME") {
        Ok(home) => home,
        Err(_) => match dirs::home_dir() {
            Some(mut home) => {
                home.push(".near");
                home.as_path().to_str().unwrap().to_string()
            }
            None => "".to_string(),
        },
    }
}

pub fn start_with_config(
    home_dir: &Path,
    config: NearConfig,
) -> (Addr<ClientActor>, Addr<ViewClientActor>) {
    let store = create_store(&get_store_path(home_dir));
    println!("Success in create store");
    let runtime = Arc::new(NightshadeRuntime::new(
        home_dir,
        store.clone(),
        config.genesis_config.clone(),
        config.client_config.tracked_accounts.clone(),
        config.client_config.tracked_shards.clone(),
    ));
    println!("Success in create runtime");

    let telemetry = TelemetryActor::new(config.telemetry_config.clone()).start();
    println!("Success in create telemetry");

    let chain_genesis = ChainGenesis::new(
        config.genesis_config.genesis_time,
        config.genesis_config.gas_limit,
        config.genesis_config.min_gas_price,
        config.genesis_config.total_supply,
        config.genesis_config.max_inflation_rate,
        config.genesis_config.gas_price_adjustment_rate,
        config.genesis_config.transaction_validity_period,
        config.genesis_config.epoch_length,
    );
    println!("Success in create runtime");

    let node_id = config.network_config.public_key.clone().into();
    let network_adapter = Arc::new(NetworkRecipient::new());
    println!("Success in create network adapter");

    let s1 = store.clone();
    println!("store cloned");
    let r2 = runtime.clone();
    println!("runtime cloned");
    let n3 = network_adapter.clone();
    println!("network adapter cloned");
    let view_client = ViewClientActor::new(s1, &chain_genesis, r2, n3).unwrap();
    println!("view client actor created");
    let view_client = view_client.start();
    println!("Success in start view client");

    let client_actor = ClientActor::new(
        config.client_config,
        store.clone(),
        chain_genesis.clone(),
        runtime,
        node_id,
        network_adapter.clone(),
        config.block_producer,
        telemetry,
    )
    .unwrap()
    .start();
    println!("Success in create client actor");

    start_http(config.rpc_config, client_actor.clone(), view_client.clone());
    println!("Success in start http");

    let network_actor = PeerManagerActor::new(
        store.clone(),
        config.network_config,
        client_actor.clone().recipient(),
        view_client.clone().recipient(),
    )
    .unwrap()
    .start();
    println!("Success in start network actor");

    network_adapter.set_recipient(network_actor.recipient());

    (client_actor, view_client)
}

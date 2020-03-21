use clap::{App, Arg, SubCommand};
use near::{get_default_home, get_store_path, load_config};
use near_chain::{ChainStore, ChainStoreAccess};
use near_store::{create_store, Store};
use std::path::Path;
use std::sync::Arc;

fn main() {
    let default_home = get_default_home();
    let matches = App::new("db-export")
        .arg(
            Arg::with_name("home")
                .long("home")
                .default_value(&default_home)
                .help("Directory for config and data (default \"~/.near\")")
                .takes_value(true),
        )
        .subcommand(SubCommand::with_name("height"))
        .get_matches();
    let home_dir = matches.value_of("home").map(|dir| Path::new(dir)).unwrap();
    let _near_config = load_config(home_dir);

    let store = create_store(&get_store_path(&home_dir));

    match matches.subcommand() {
        ("height", _) => export_height(store),
        _ => unreachable!(),
    }
}

fn export_height(store: Arc<Store>) {
    let mut chain_store = ChainStore::new(store.clone());

    let head = chain_store.head().unwrap();
    let last_block = chain_store.get_block(&head.last_block_hash).unwrap().clone();
    println!("{}", last_block.header.inner_lite.height);
}

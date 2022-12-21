use clap::Parser;
use ethers::prelude::*;
use ethers::providers::{Http, Middleware, Provider};
use ethers::utils::get_contract_address;
use std::str::FromStr;
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
};
use std::fs::File;
use std::path::Path;
use test_tvx::{EvmContractBalance, EvmContractContext, EvmContractInput, EvmContractState, export_test_vector_file};

const OP_SSTORE: &str = "SSTORE";
const OP_SLOAD: &str = "SLOAD";

const OP_CALL: &str = "CALL";
const OP_STATICCALL: &str = "STATICCALL";
const OP_CALLCODE: &str = "CALLCODE";
const OP_DELEGATECALL: &str = "DELEGATECALL";

const OP_BALANCE: &str = "BALANCE";
const OP_SELFBALANCE: &str = "SELFBALANCE";

const OP_CREATE: &str = "CREATE";
const OP_CREATE2: &str = "CREATE2";

#[derive(Parser, Debug)]
#[clap(name = env!("CARGO_PKG_NAME"))]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Generate a test vector by extracting it from a live chain.", long_about = None)]
struct Cli {
    #[clap(default_value = "http://localhost:8545", short, long)]
    geth_rpc_endpoint: String,

    /// eth transaction hash
    #[clap(short, long)]
    tx_hash: String,

    /// test-vector file output path ( such as: /a/b/xx/xxx.json )
    #[clap(short, long)]
    out: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let tx_hash = H256::from_str(&cli.tx_hash)?;

    let provider = Provider::<Http>::try_from(cli.geth_rpc_endpoint)
        .expect("could not instantiate HTTP Provider");

    let transaction = provider.get_transaction(tx_hash).await?.unwrap();

    let block = provider
        .get_block_with_txs(transaction.block_hash.unwrap())
        .await?
        .unwrap();

    let block_transactions = &block.transactions;

    let tx_from = transaction.from;
    let tx_callee = transaction
        .to
        .unwrap_or_else(|| get_contract_address(tx_from, transaction.nonce));

    let mut execution_context = vec![tx_callee];

    let mut pre_storages = BTreeMap::new();
    let mut post_storages = BTreeMap::new();

    let mut pre_balances = BTreeMap::new();
    let mut post_balances = BTreeMap::new();
    let mut post_balances_negative = BTreeMap::new();

    // transaction value transfer
    post_balances.insert(tx_callee, transaction.value);
    post_balances.insert(tx_from, U256::zero());
    post_balances_negative.insert(tx_from, transaction.value);

    let mut pre_codes = BTreeMap::new();
    let mut post_codes = BTreeMap::new();

    // TODO some contracts may have "selfdestructed"
    let code = provider.get_code(tx_callee, None).await?;
    if transaction.to.is_some() {
        pre_codes.insert(tx_callee, code.clone());
    }
    post_codes.insert(tx_callee, code);

    // trace current transaction
    let trace_options: GethDebugTracingOptions = GethDebugTracingOptions::default();
    let transaction_trace = provider
        .debug_trace_transaction(tx_hash, trace_options.clone())
        .await?;

    let mut depth = 1u64;
    for log in transaction_trace.struct_logs {
        if depth < log.depth {
            println!("{log:?}");
            execution_context.pop();
            depth = log.depth;
        }

        match log.op.as_str() {
            OP_SLOAD => {
                let mut stack = log.stack.unwrap();

                let key = stack.pop().unwrap();

                let mut bytes = [0; 32];
                key.to_big_endian(&mut bytes);
                let log_storage = log.storage.unwrap();
                let val = log_storage.get(&H256::from_slice(&bytes)).unwrap();
                let val = U256::from_big_endian(val.as_bytes());

                pre_storages
                    .entry(*execution_context.last().unwrap())
                    .or_insert(HashMap::new())
                    .entry(key)
                    .or_insert(val);

                post_storages
                    .entry(*execution_context.last().unwrap())
                    .or_insert(HashMap::new())
                    .insert(key, val);
            }
            OP_SSTORE => {
                let mut stack = log.stack.unwrap();

                let key = stack.pop().unwrap();
                let val = stack.pop().unwrap();

                post_storages
                    .entry(*execution_context.last().unwrap())
                    .or_insert(HashMap::new())
                    .insert(key, val);
            }
            OP_CALL => {
                depth += 1;

                let stack = log.stack.unwrap();

                let address = decode_address(stack[stack.len() - 2]);

                let value = stack[stack.len() - 3];
                let caller = *execution_context.last().unwrap();
                post_balances.insert(address, value);
                post_balances_negative.insert(caller, value);

                execution_context.push(address);

                if pre_codes.get(&address).is_none() {
                    let code = provider.get_code(address, None).await?;
                    pre_codes.insert(address, code.clone());
                    post_codes.insert(address, code);
                }
            }
            OP_STATICCALL => {
                depth += 1;

                let stack = log.stack.unwrap();

                let address = decode_address(stack[stack.len() - 2]);

                execution_context.push(address);

                if pre_codes.get(&address).is_none() {
                    let code = provider.get_code(address, None).await?;
                    pre_codes.insert(address, code.clone());
                    post_codes.insert(address, code);
                }
            }
            OP_DELEGATECALL => {
                depth += 1;

                let stack = log.stack.unwrap();

                let address = decode_address(stack[stack.len() - 2]);

                execution_context.push(*execution_context.last().unwrap());

                if pre_codes.get(&address).is_none() {
                    let code = provider.get_code(address, None).await?;
                    pre_codes.insert(address, code.clone());
                    post_codes.insert(address, code);
                }
            }
            OP_CALLCODE => {
                depth += 1;

                let stack = log.stack.unwrap();

                let address = decode_address(stack[stack.len() - 2]);

                execution_context.push(*execution_context.last().unwrap());

                if pre_codes.get(&address).is_none() {
                    let code = provider.get_code(address, None).await?;
                    pre_codes.insert(address, code.clone());
                    post_codes.insert(address, code);
                }
            }
            OP_CREATE => {
                depth += 1;
                // TODO post-transaction state
                // FIXME
                execution_context.push(*execution_context.last().unwrap());
            }
            OP_CREATE2 => {
                depth += 1;
                // TODO
                // FIXME
                execution_context.push(*execution_context.last().unwrap());
            }
            _ => (),
        }
    }

    // Get balances of associated accounts.
    // Since we can't get accurate balance just before the tx was executed from ethereum JSON RPC,
    // We need first get the balance at previous block and then trace the preceding txs of this tx.
    let prev_block_number = block.number.unwrap() - 1;
    for address in post_balances.keys() {
        let balance = provider
            .get_balance(*address, Some(prev_block_number.into()))
            .await
            .unwrap();
        pre_balances.insert(*address, balance);
    }

    for preceding_tx in block_transactions {
        if preceding_tx.transaction_index == transaction.transaction_index {
            break;
        }

        let from = transaction.from;
        let to = match preceding_tx.to {
            Some(to) => to,
            None => get_contract_address(from, transaction.nonce),
        };

        if !preceding_tx.value.is_zero() {
            if let Some(v) = pre_balances.get_mut(&from) {
                *v -= preceding_tx.value;
            }

            if let Some(v) = pre_balances.get_mut(&from) {
                *v += preceding_tx.value;
            }
        }

        let mut execution_context = vec![to];

        let trace = provider
            .debug_trace_transaction(preceding_tx.hash, trace_options.clone())
            .await
            .unwrap();

        let mut depth = 1u64;
        for log in trace.struct_logs {
            if depth < log.depth {
                execution_context.pop();
                depth -= 1;
            }

            match log.op.as_str() {
                OP_CALL => {
                    depth += 1;

                    let stack = log.stack.unwrap();

                    let callee = decode_address(stack[stack.len() - 2]);
                    let caller = execution_context.last().unwrap();

                    let value = stack[stack.len() - 3];

                    if let Some(balance) = pre_balances.get_mut(caller) {
                        *balance -= value;
                    }

                    if let Some(balance) = pre_balances.get_mut(&callee) {
                        *balance -= value;
                    }

                    execution_context.push(callee);
                }
                OP_STATICCALL => {
                    depth += 1;

                    let stack = log.stack.unwrap();

                    let address = decode_address(stack[stack.len() - 2]);

                    execution_context.push(address);
                }
                OP_DELEGATECALL => {
                    depth += 1;
                    execution_context.push(*execution_context.last().unwrap());
                }
                OP_CALLCODE => {
                    depth += 1;
                    execution_context.push(*execution_context.last().unwrap());
                }
                OP_CREATE => {
                    depth += 1;
                    // TODO post-transaction state
                    // FIXME
                    execution_context.push(*execution_context.last().unwrap());
                }
                OP_CREATE2 => {
                    depth += 1;
                    // TODO
                    // FIXME
                    execution_context.push(*execution_context.last().unwrap());
                }
                OP_BALANCE => {
                    let stack = log.stack.unwrap();

                    let address = decode_address(stack[stack.len() - 1]);
                    post_balances.entry(address).or_insert(U256::zero());
                }
                OP_SELFBALANCE => {
                    let address = *execution_context.last().unwrap();
                    post_balances.entry(address).or_insert(U256::zero());
                }
                _ => (),
            }
        }
    }

    for (address, balance) in post_balances.iter_mut() {
        let pre_balance = pre_balances.get(address).unwrap();
        *balance += *pre_balance;

        if let Some(subtrahend) = post_balances_negative.get(address) {
            *balance -= *subtrahend;
        }
    }

    let status =  if transaction_trace.failed { 0 } else { 1 };
    let return_result = hex::encode(transaction_trace.return_value.to_vec());

    let input = eth_tx_to_input(transaction,
                                block,
                                pre_storages,
                                post_storages,
                                pre_balances,
                                post_balances,
                                pre_codes,
                                post_codes,
                                status,
                                return_result);

    export_test_vector_file(
        input,
        Path::new(&cli.out).to_path_buf(),
    ).await?;

    Ok(())
}

fn decode_address(raw_address: U256) -> H160 {
    let mut bytes = [0; 32];
    raw_address.to_big_endian(&mut bytes);
    H160::from_slice(&bytes[12..])
}


fn push_adds<T>(adds: &mut Vec<Address> ,bmap: &BTreeMap<Address, T>) {
    bmap.keys().for_each(|addr| {
        if !adds.contains(addr) {
            adds.push(addr.clone());
        }
    });
}

fn get_storage(addr: &Address, storages: &BTreeMap<Address, HashMap<U256, U256>>) -> HashMap<String, String> {
    let bmap = storages.get(&addr);
    let mut vmap = HashMap::new();
    if let Some(bmap) = bmap {
        for (k, v) in bmap {
            vmap.insert(u256_to_str(k), u256_to_str(v));
        }
    }
    vmap
}

fn get_balance(addr: &Address, balances: &BTreeMap<Address, U256>) -> String {
    match balances.get(&addr) {
        Some(v) => u256_to_str(v),
        None => String::from("00")
    }
}

fn get_code(addr: &Address, codes: &BTreeMap<Address, Bytes>) -> Option<String> {
    match codes.get(&addr) {
        Some(v) => {
            Some(hex::encode(v.to_vec()))
        },
        None => None
    }
}

fn get_eth_addr(addr: Option<Address>) -> String {
    match addr {
        Some(addr) => hex::encode(addr.0),
        None => String::from("0x00")
    }
}

fn u256_to_str(v: &U256) -> String {
    let mut value = [0u8; 32];
    v.to_big_endian(&mut value);
    hex::encode(value)
}

fn h256_to_str(v: &H256) -> String {
    hex::encode(v.0)
}

fn eth_tx_to_input(transaction: Transaction,
                   block: Block<Transaction>,
                   pre_storages: BTreeMap<Address, HashMap<U256, U256>>,
                   post_storages: BTreeMap<Address, HashMap<U256, U256>>,
                   pre_balances: BTreeMap<Address, U256>,
                   post_balances: BTreeMap<Address, U256>,
                   pre_codes: BTreeMap<Address, Bytes>,
                   post_codes: BTreeMap<Address, Bytes>,
                   status: usize,
                   return_result: String) -> EvmContractInput {
    let mut adds: Vec<Address> = Vec::new();
    push_adds(&mut adds, &pre_storages);
    push_adds(&mut adds, &post_storages);
    push_adds(&mut adds, &pre_balances);
    push_adds(&mut adds, &post_balances);
    push_adds(&mut adds, &pre_codes);
    push_adds(&mut adds, &post_codes);

    let mut states = HashMap::<String, EvmContractState>::new();
    let mut balances = HashMap::<String, EvmContractBalance>::new();
    for addr in adds {
        let eth_addr = get_eth_addr(Some(addr));
        let pre_storage = get_storage(&addr, &pre_storages);
        let post_storage = get_storage(&addr, &post_storages);
        let pre_balance = get_balance(&addr, &pre_balances);
        let post_balance = get_balance(&addr, &post_balances);
        let pre_code = get_code(&addr, &pre_codes);
        let post_code = get_code(&addr, &post_codes);
        states.insert(eth_addr.clone(), EvmContractState {
            pre_storage,
            post_storage,
            pre_code,
            post_code
        });
        balances.insert(eth_addr, EvmContractBalance {
            pre_balance,
            post_balance
        });
    }

    let mut transactions: Vec<String> = Vec::new();
    for t in block.transactions {
        transactions.push(match t.block_hash { Some(v) => h256_to_str(&v), None => String::from("00") });
    }

    let context: EvmContractContext = EvmContractContext {
        chain_id: match transaction.chain_id { Some(v) => v.as_u64(), None => 0 },
        from: get_eth_addr(Some(transaction.from)),
        to: get_eth_addr(transaction.to),
        input: hex::encode(transaction.input.to_vec()),
        value: u256_to_str(&transaction.value),
        gas_price: match transaction.gas_price { Some(v) => u256_to_str(&v), None => String::from("00") },
        gas_limit: transaction.gas.as_u64(),
        gas_fee_cap: match transaction.max_fee_per_gas { Some(v) => u256_to_str(&v), None => String::from("00") },
        gas_tip_cap: match transaction.max_priority_fee_per_gas { Some(v) => u256_to_str(&v), None => String::from("00") },
        block_number: match transaction.block_number { Some(v) => v.as_u64(), None => 0 },
        timestamp: block.timestamp.as_usize(),
        nonce: transaction.nonce.as_u64(),
        block_hash: match transaction.block_hash { Some(v) => h256_to_str(&v), None => String::from("00") },
        block_difficulty: block.difficulty.as_usize(),
        status,
        return_result
    };

    EvmContractInput {
        states,
        balances,
        transactions,
        context
    }
}

use ethers::prelude::*;
use ethers::providers::{Http, Middleware, Provider};
use ethers::utils::get_contract_address;
use std::str::FromStr;
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
};

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let tx_hash = "0x29c237b7eacede6b2a8060192ea7634b187382bc1117690d5e92d3b6824da4f2";
    let tx_hash = H256::from_str(tx_hash).unwrap();

    let provider = Provider::<Http>::try_from("http://localhost:8545")
        .expect("could not instantiate HTTP Provider");

    let transaction = provider.get_transaction(tx_hash).await?.unwrap();

    let block = provider
        .get_block_with_txs(transaction.block_hash.unwrap())
        .await?
        .unwrap();

    let block_transactions = block.transactions;

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

    println!("pre-transaction: {pre_storages:?}");
    println!("post-transaction: {post_storages:?}");
    Ok(())
}

fn decode_address(raw_address: U256) -> H160 {
    let mut bytes = [0; 32];
    raw_address.to_big_endian(&mut bytes);
    H160::from_slice(&bytes[12..])
}

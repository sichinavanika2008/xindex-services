//! Canonical Safe v1.4.1 on-chain submission qualification.
//!
//! This test is deliberately RPC-independent. It stages the exact published
//! Safe singleton and proxy-factory runtimes at their canonical addresses on a
//! fresh Anvil node, verifies both runtime hashes against `safe-deployments`,
//! and then deploys a real 3-of-3 Safe proxy through the canonical factory.
//! No mock Safe is involved and no production chain-registry address changes.

use std::time::Duration;

use alloy::node_bindings::Anvil;
use alloy::signers::{local::PrivateKeySigner, Signer, SignerSync};
use alloy_primitives::{keccak256, Address, B256, Bytes, U256};
use alloy_sol_types::{sol, SolCall};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};
use xindex_chain_evm::{build_safe_exec_tx_request, EvmTxFee};
use xindex_safe_evm::digest::{safe_tx_hash, SafeTransaction};
use xindex_safe_evm::exec::build_exec_transaction_calldata;
use xindex_safe_evm::sigs::{aggregate_signatures, EcdsaSig, SignedBy};
use xindex_safe_evm::SafeOperation;
use xindex_shared::chain_registry::ChainId;

const SAFE_SINGLETON: &str = "0x41675C099F32341bf84BFc5382aF534df5C7461a";
const SAFE_SINGLETON_CODE_HASH: &str =
    "0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4";
const SAFE_PROXY_FACTORY: &str = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67";
const SAFE_PROXY_FACTORY_CODE_HASH: &str =
    "0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317";

const SAFE_RUNTIME: &str = include_str!("fixtures/safe-v1.4.1-runtime.hex");
const SAFE_PROXY_FACTORY_RUNTIME: &str =
    include_str!("fixtures/safe-proxy-factory-v1.4.1-runtime.hex");

const OWNER_KEYS: [&str; 3] = [
    "0x1111111111111111111111111111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333333333333333333333333333",
];

sol! {
    function setup(
        address[] _owners,
        uint256 _threshold,
        address to,
        bytes data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    );

    function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce)
        returns (address proxy);

    function nonce() view returns (uint256);
    function getThreshold() view returns (uint256);
}

async fn rpc(client: &Client, endpoint: &str, method: &str, params: Value) -> Result<Value> {
    let response = client
        .post(endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .with_context(|| format!("RPC {method}"))?
        .error_for_status()
        .with_context(|| format!("RPC HTTP status for {method}"))?;
    let body: Value = response
        .json()
        .await
        .with_context(|| format!("decode RPC response for {method}"))?;
    if let Some(error) = body.get("error").filter(|value| !value.is_null()) {
        bail!("RPC {method} failed: {error}");
    }
    body.get("result")
        .cloned()
        .with_context(|| format!("RPC {method} omitted result"))
}

fn rpc_string(value: Value, label: &str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("{label} was not a string: {value}"))
}

async fn wait_for_receipt(client: &Client, endpoint: &str, hash: &str) -> Result<Value> {
    for _ in 0..100 {
        let receipt = rpc(client, endpoint, "eth_getTransactionReceipt", json!([hash])).await?;
        if !receipt.is_null() {
            return Ok(receipt);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("timed out waiting for receipt {hash}")
}

fn decode_data(encoded: &str) -> Result<Vec<u8>> {
    alloy_primitives::hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded))
        .with_context(|| format!("invalid hex data: {encoded}"))
}

fn decode_quantity(encoded: &str) -> Result<U256> {
    let digits = encoded.strip_prefix("0x").unwrap_or(encoded);
    if digits.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(digits, 16).with_context(|| format!("invalid quantity: {encoded}"))
}

fn encode_data(bytes: &[u8]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(bytes))
}

fn quantity(value: u128) -> String {
    format!("0x{value:x}")
}

async fn call_word(client: &Client, endpoint: &str, to: Address, data: &[u8]) -> Result<U256> {
    let result = rpc_string(
        rpc(
            client,
            endpoint,
            "eth_call",
            json!([{
                "to": format!("{to:#x}"),
                "data": encode_data(data),
            }, "latest"]),
        )
        .await?,
        "eth_call result",
    )?;
    let bytes = decode_data(&result)?;
    if bytes.len() != 32 {
        bail!("eth_call returned {} bytes, expected one ABI word", bytes.len());
    }
    Ok(U256::from_be_slice(&bytes))
}

async fn balance(client: &Client, endpoint: &str, address: Address) -> Result<U256> {
    let encoded = rpc_string(
        rpc(
            client,
            endpoint,
            "eth_getBalance",
            json!([format!("{address:#x}"), "latest"]),
        )
        .await?,
        "eth_getBalance result",
    )?;
    decode_quantity(&encoded)
}

fn assert_success(receipt: &Value, label: &str) -> Result<()> {
    let status = receipt
        .get("status")
        .and_then(Value::as_str)
        .with_context(|| format!("{label} receipt omitted status"))?;
    if status != "0x1" {
        bail!("{label} reverted: {receipt}");
    }
    Ok(())
}

#[tokio::test]
async fn canonical_safe_v141_executes_3_of_3_and_rejects_replay_on_local_anvil() -> Result<()> {
    let anvil = Anvil::new().chain_id(1).spawn();
    let endpoint = anvil.endpoint();
    let client = Client::new();

    let singleton: Address = SAFE_SINGLETON.parse().context("Safe singleton address")?;
    let factory: Address = SAFE_PROXY_FACTORY.parse().context("Safe factory address")?;
    let singleton_hash: B256 = SAFE_SINGLETON_CODE_HASH.parse().context("singleton hash")?;
    let factory_hash: B256 = SAFE_PROXY_FACTORY_CODE_HASH.parse().context("factory hash")?;
    let singleton_runtime = decode_data(SAFE_RUNTIME.trim())?;
    let factory_runtime = decode_data(SAFE_PROXY_FACTORY_RUNTIME.trim())?;

    // The fixtures must remain byte-identical to Safe's released canonical
    // deployment metadata. A fixture edit fails before any contract executes.
    assert_eq!(keccak256(&singleton_runtime), singleton_hash);
    assert_eq!(keccak256(&factory_runtime), factory_hash);

    rpc(
        &client,
        &endpoint,
        "anvil_setCode",
        json!([format!("{singleton:#x}"), SAFE_RUNTIME.trim()]),
    )
    .await?;
    rpc(
        &client,
        &endpoint,
        "anvil_setCode",
        json!([format!("{factory:#x}"), SAFE_PROXY_FACTORY_RUNTIME.trim()]),
    )
    .await?;

    for (address, expected_hash) in [(singleton, singleton_hash), (factory, factory_hash)] {
        let code = rpc_string(
            rpc(
                &client,
                &endpoint,
                "eth_getCode",
                json!([format!("{address:#x}"), "latest"]),
            )
            .await?,
            "eth_getCode result",
        )?;
        assert_eq!(keccak256(decode_data(&code)?), expected_hash);
    }

    let accounts = rpc(&client, &endpoint, "eth_accounts", json!([])).await?;
    let submitter_text = accounts
        .as_array()
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .context("Anvil returned no unlocked submitter")?;
    let submitter: Address = submitter_text.parse().context("submitter address")?;

    let owner_signers: Vec<PrivateKeySigner> = OWNER_KEYS
        .iter()
        .map(|key| key.parse().with_context(|| format!("owner key {key}")))
        .collect::<Result<_>>()?;
    let owner_addresses: Vec<Address> = owner_signers.iter().map(Signer::address).collect();
    let initializer = setupCall {
        _owners: owner_addresses,
        _threshold: U256::from(3),
        to: Address::ZERO,
        data: Bytes::new(),
        fallbackHandler: Address::ZERO,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    }
    .abi_encode();
    let factory_calldata = createProxyWithNonceCall {
        _singleton: singleton,
        initializer: initializer.into(),
        saltNonce: U256::from(0x5849_u64),
    }
    .abi_encode();

    let deployment_hash = rpc_string(
        rpc(
            &client,
            &endpoint,
            "eth_sendTransaction",
            json!([{
                "from": format!("{submitter:#x}"),
                "to": format!("{factory:#x}"),
                "data": encode_data(&factory_calldata),
                "gas": quantity(1_000_000),
            }]),
        )
        .await?,
        "factory transaction hash",
    )?;
    let deployment_receipt = wait_for_receipt(&client, &endpoint, &deployment_hash).await?;
    assert_success(&deployment_receipt, "Safe proxy deployment")?;

    let creation_topic = format!("{:#x}", keccak256(b"ProxyCreation(address,address)"));
    let creation_log = deployment_receipt
        .get("logs")
        .and_then(Value::as_array)
        .and_then(|logs| {
            logs.iter().find(|log| {
                log.get("topics")
                    .and_then(Value::as_array)
                    .and_then(|topics| topics.first())
                    .and_then(Value::as_str)
                    .is_some_and(|topic| topic.eq_ignore_ascii_case(&creation_topic))
            })
        })
        .context("Safe factory receipt omitted ProxyCreation")?;
    let proxy_topic = creation_log
        .get("topics")
        .and_then(Value::as_array)
        .and_then(|topics| topics.get(1))
        .and_then(Value::as_str)
        .context("ProxyCreation omitted indexed proxy")?;
    if proxy_topic.len() < 40 {
        bail!("malformed ProxyCreation proxy topic: {proxy_topic}");
    }
    let proxy: Address = format!("0x{}", &proxy_topic[proxy_topic.len() - 40..])
        .parse()
        .context("proxy address")?;

    assert_eq!(
        call_word(&client, &endpoint, proxy, &getThresholdCall {}.abi_encode()).await?,
        U256::from(3)
    );
    assert_eq!(
        call_word(&client, &endpoint, proxy, &nonceCall {}.abi_encode()).await?,
        U256::ZERO
    );

    const SAFE_BALANCE: u128 = 1_000_000_000_000_000_000;
    const TRANSFER_VALUE: u128 = 1_000_000_000_000_000;
    rpc(
        &client,
        &endpoint,
        "anvil_setBalance",
        json!([format!("{proxy:#x}"), quantity(SAFE_BALANCE)]),
    )
    .await?;
    let recipient = Address::repeat_byte(0x77);
    let recipient_before = balance(&client, &endpoint, recipient).await?;

    let safe_tx = SafeTransaction {
        to: recipient,
        value: U256::from(TRANSFER_VALUE),
        data: Bytes::new(),
        operation: SafeOperation::Call,
        safe_tx_gas: U256::ZERO,
        base_gas: U256::ZERO,
        gas_price: U256::ZERO,
        gas_token: Address::ZERO,
        refund_receiver: Address::ZERO,
        nonce: U256::ZERO,
    };
    let digest = safe_tx_hash(1, proxy, &safe_tx);
    let signatures = owner_signers
        .iter()
        .map(|signer| {
            let signature = signer.sign_hash_sync(&digest).context("sign Safe digest")?;
            let encoded = signature.as_bytes();
            Ok(SignedBy {
                signer: signer.address(),
                sig: EcdsaSig::from_65_bytes(encoded).context("decode Safe signature")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let signature_blob = aggregate_signatures(digest, &signatures)?;
    let exec_calldata = build_exec_transaction_calldata(&safe_tx, signature_blob);
    let fee = EvmTxFee {
        gas_limit: 500_000,
        max_fee_per_gas: 10_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        gas_price: 0,
    };
    let request = build_safe_exec_tx_request(
        ChainId::Eth,
        submitter,
        proxy,
        exec_calldata,
        fee,
    )
    .context("build Safe wrapper request")?;
    assert_eq!(request.from, Some(submitter));
    assert_eq!(request.to, Some(proxy.into()));
    assert_eq!(request.chain_id, Some(1));
    let wrapper_data = request
        .input
        .input
        .as_ref()
        .context("wrapper request omitted calldata")?;

    let wrapper = json!({
        "from": format!("{submitter:#x}"),
        "to": format!("{proxy:#x}"),
        "data": encode_data(wrapper_data),
        "gas": quantity(u128::from(fee.gas_limit)),
        "maxFeePerGas": quantity(fee.max_fee_per_gas),
        "maxPriorityFeePerGas": quantity(fee.max_priority_fee_per_gas),
    });
    let execution_hash = rpc_string(
        rpc(
            &client,
            &endpoint,
            "eth_sendTransaction",
            json!([wrapper.clone()]),
        )
        .await?,
        "Safe execution transaction hash",
    )?;
    let execution_receipt = wait_for_receipt(&client, &endpoint, &execution_hash).await?;
    assert_success(&execution_receipt, "Safe execution")?;

    assert_eq!(
        call_word(&client, &endpoint, proxy, &nonceCall {}.abi_encode()).await?,
        U256::from(1)
    );
    assert_eq!(
        balance(&client, &endpoint, recipient).await?,
        recipient_before + U256::from(TRANSFER_VALUE)
    );
    assert_eq!(
        balance(&client, &endpoint, proxy).await?,
        U256::from(SAFE_BALANCE - TRANSFER_VALUE)
    );

    // Re-submitting the exact signed payload binds to stale Safe nonce 0 and
    // must revert. The Safe nonce and balances remain unchanged.
    let replay_hash = rpc_string(
        rpc(
            &client,
            &endpoint,
            "eth_sendTransaction",
            json!([wrapper]),
        )
        .await?,
        "replay transaction hash",
    )?;
    let replay_receipt = wait_for_receipt(&client, &endpoint, &replay_hash).await?;
    assert_eq!(replay_receipt.get("status").and_then(Value::as_str), Some("0x0"));
    assert_eq!(
        call_word(&client, &endpoint, proxy, &nonceCall {}.abi_encode()).await?,
        U256::from(1)
    );
    assert_eq!(
        balance(&client, &endpoint, recipient).await?,
        recipient_before + U256::from(TRANSFER_VALUE)
    );

    Ok(())
}

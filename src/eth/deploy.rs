//! Utility functions for deploying and verifying on EVM.
use ethers::{
    abi::Abi,
    contract::ContractFactory,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, TransactionReceipt, TransactionRequest},
};
use eyre::{eyre, Result};
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier::loader::evm::encode_calldata;
use snark_verifier::loader::evm::ExecutorBuilder;
use std::{sync::Arc, time::Duration};

/// Dry runs a given EVM contract locally using `revm`, returning the gas used.
pub fn dry_run_verifier(
    deployment_code: Vec<u8>,
    instances: Vec<Vec<Fr>>,
    proof: Vec<u8>,
) -> Result<u64> {
    let calldata = encode_calldata(&instances, &proof);
    let mut evm = ExecutorBuilder::default()
        .with_gas_limit(u64::MAX.into())
        .build();

    let caller = Address::from_low_u64_be(0xfe);
    let deployment_result = evm.deploy(caller, deployment_code.into(), 0.into());

    let verifier = deployment_result.address;
    match verifier {
        Some(verifier) => {
            let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

            if !result.reverted {
                Ok(result.gas_used)
            } else {
                Err(eyre!("Verifier reverted"))
            }
        }
        None => Err(eyre!(
            "Verifier deployment failed: {:?}",
            deployment_result.exit_reason
        )),
    }
}

fn print_receipt(receipt: TransactionReceipt) {
    println!("== Transaction summary");
    println!("  Transaction hash: {:?}", receipt.transaction_hash);
    println!("  Deployed at block: {:?}", receipt.block_number);
    println!("  Gas used: {:?}", receipt.gas_used.unwrap());
}

/// Deploys an EVM contract.
pub async fn deploy_contract(
    endpoint: String,
    wallet: LocalWallet,
    deployment_code: Vec<u8>,
) -> Result<Address> {
    let provider = Provider::<Http>::try_from(endpoint)?.interval(Duration::from_millis(10u64));
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));
    let client = Arc::new(client);

    let factory = ContractFactory::new(Abi::default(), deployment_code.into(), client.clone());

    let (contract, deploy_receipt) = factory.deploy(())?.send_with_receipt().await?;
    print_receipt(deploy_receipt);
    println!("Deployed to address: {:?}", contract.address());

    Ok(contract.address())
}

/// Submits a proof to an EVM contract.
pub async fn submit_proof(
    endpoint: String,
    wallet: LocalWallet,
    contract_address: Address,
    proof: Vec<u8>,
    instances: Vec<Vec<Fr>>,
) -> Result<()> {
    let provider = Provider::<Http>::try_from(endpoint)?.interval(Duration::from_millis(10u64));
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));
    let client = Arc::new(client);

    let calldata = encode_calldata(&instances, &proof);

    let tx = TransactionRequest::new()
        .to(contract_address)
        .data(calldata);
    let receipt = client
        .send_transaction(tx, None)
        .await?
        .await?
        .ok_or(eyre!("No receipt!"))?;

    print_receipt(receipt);

    Ok(())
}

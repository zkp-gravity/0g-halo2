use ethers::{
    abi::Abi,
    contract::ContractFactory,
    core::utils::Anvil,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, TransactionReceipt, TransactionRequest},
    utils::AnvilInstance,
};
use eyre::{eyre, Result};
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier::loader::evm::encode_calldata;
use snark_verifier::loader::evm::ExecutorBuilder;
use std::{sync::Arc, time::Duration};

pub fn verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();

        let caller = Address::from_low_u64_be(0xfe);
        let deployment_result = evm.deploy(caller, deployment_code.into(), 0.into());

        let verifier = deployment_result.address;
        match verifier {
            Some(verifier) => {
                let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

                dbg!(result.gas_used);

                !result.reverted
            }
            None => {
                println!("Deployment result: {:?}", deployment_result.exit_reason);
                false
            }
        }
    };
    assert!(success);
}

pub fn spawn_anvil() -> (AnvilInstance, LocalWallet) {
    let anvil = Anvil::new().spawn();
    let chain_id = anvil.chain_id();
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    (anvil, wallet.with_chain_id(chain_id))
}

fn print_receipt(receipt: TransactionReceipt) {
    println!("== Transaction summary");
    println!("  Transaction hash: {:?}", receipt.transaction_hash);
    println!("  Deployed at block: {:?}", receipt.block_number);
    println!("  Gas used: {:?}", receipt.gas_used.unwrap());
}

pub async fn deploy_contract(
    deployment_code: Vec<u8>,
    endpoint: String,
    wallet: LocalWallet,
) -> Result<Address> {
    // 3. connect to the network
    let provider = Provider::<Http>::try_from(endpoint)?.interval(Duration::from_millis(10u64));

    // 4. instantiate the client with the wallet
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    // 5. create a factory which will be used to deploy instances of the contract
    let factory = ContractFactory::new(Abi::default(), deployment_code.into(), client.clone());

    // 6. deploy it with the constructor arguments
    let deployer = factory.deploy(())?;
    let (contract, deploy_receipt) = deployer.send_with_receipt().await?;
    print_receipt(deploy_receipt);
    println!("Deployed at address: {:?}", contract.address());

    Ok(contract.address())
}

pub async fn submit_proof(
    instances: Vec<Vec<Fr>>,
    proof: Vec<u8>,
    endpoint: String,
    wallet: LocalWallet,
    contract_address: Address,
) -> Result<()> {
    let calldata = encode_calldata(&instances, &proof);

    let provider = Provider::<Http>::try_from(endpoint)?.interval(Duration::from_millis(10u64));
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

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

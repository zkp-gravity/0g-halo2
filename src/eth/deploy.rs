use ethers::{
    abi::Abi,
    contract::ContractFactory,
    core::utils::Anvil,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::TransactionRequest,
};
use eyre::{eyre, Result};
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier::loader::evm::encode_calldata;
use snark_verifier::loader::evm::{Address, ExecutorBuilder};
use std::{sync::Arc, time::Duration};

pub fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
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

pub async fn evm_deploy(
    deployment_code: Vec<u8>,
    instances: Vec<Vec<Fr>>,
    proof: Vec<u8>,
) -> Result<()> {
    let calldata = encode_calldata(&instances, &proof);

    // 2. instantiate our wallet & anvil
    let anvil = Anvil::new().spawn();
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    // 3. connect to the network
    let provider =
        Provider::<Http>::try_from(anvil.endpoint())?.interval(Duration::from_millis(10u64));

    // 4. instantiate the client with the wallet
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id()));
    let client = Arc::new(client);

    // 5. create a factory which will be used to deploy instances of the contract
    let factory = ContractFactory::new(Abi::default(), deployment_code.into(), client.clone());

    // 6. deploy it with the constructor arguments
    let deployer = factory.deploy(())?;
    let (contract, deploy_receipt) = deployer.send_with_receipt().await?;
    println!("Transaction hash: {:?}", deploy_receipt.transaction_hash);
    println!("Deployed at block: {:?}", deploy_receipt.block_number);
    println!("Deployed at address: {:?}", contract.address());
    println!(
        "Deployed at gas used: {:?}",
        deploy_receipt.gas_used.unwrap()
    );

    // 7. get the contract's address
    let addr = contract.address();

    let tx = TransactionRequest::new().to(addr).data(calldata);
    let receipt = client
        .send_transaction(tx, None)
        .await?
        .await?
        .ok_or(eyre!("No receipt!"))?;

    println!("Receipt: {:?}", receipt);

    Ok(())
}

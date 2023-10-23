use assert_matches::assert_matches;
use rand::thread_rng;
use solana_program_test::*;
use solana_sdk::{
    bls12_381_instruction::new_bls_12_381_instruction,
    bls12_381_instruction::generate_key, 
	signature::Signer,
    transaction::{Transaction, TransactionError},
};


#[tokio::test]
async fn test_success() {
    let mut context = ProgramTest::default().start_with_context().await;

    let client = &mut context.banks_client;
    let payer = &context.payer;
    let recent_blockhash = context.last_blockhash;

    let privkey = generate_key(&mut thread_rng());
    let message_arr = b"hello";
    let instruction = new_bls_12_381_instruction(&privkey, message_arr);

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[payer],
        recent_blockhash,
    );

    assert_matches!(client.process_transaction(transaction).await, Ok(()));
}

use solana_sdk::bls12_381_instruction::{pair::GeneratorPoint, SignKey, VerKey};

use {
    solana_program_test::*,
};

#[tokio::test]
async fn test_success() {
    // let mut context = ProgramTest::default().start_with_context().await;

    // let client = &mut context.banks_client;
    // let payer = &context.payer;
    // let recent_blockhash = context.last_blockhash;

    let message = b"Hello world";
    let gen = GeneratorPoint::new();
    let sign_key = SignKey::new(None).unwrap();
    let ver_key = VerKey::new(gen, &sign_key);
    let signature = sign_key.sign(message).unwrap();

    assert!(signature.verify(message, &ver_key, gen).unwrap());

    // TODO: instruction API. It's not strictly necessary, but it
    // allows more of this code to be kept upstream as a dynamically
    // linkable code executable. At the same time, it's also extremely
    // tricky to get right.
    //
    // If we want upstream compatibility, we have to get this in a
    // form that is compatible with the original SIMD.
}

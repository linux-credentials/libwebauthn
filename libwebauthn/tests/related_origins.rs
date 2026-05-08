use libwebauthn::ops::webauthn::related_origins::validate_related_origins;

#[tokio::test]
async fn amazon_validate_related_origins() -> Result<(), Box<dyn std::error::Error>> {
    let caller_origin = "https://www.amazon.com";
    let rp_id = "amazon.com";

    let res = validate_related_origins(caller_origin, rp_id).await?;
    assert!(res, "Expected related origins validation to succeed for Amazon");
    Ok(())
}

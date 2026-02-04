use libwebauthn::ops::webauthn::related_origins::validate_related_origins;
use libwebauthn::ops::webauthn::related_origins::client::ReqwestRelatedOriginsClient;

#[tokio::test]
async fn amazon_validate_related_origins() -> Result<(), Box<dyn std::error::Error>> {
    let client = ReqwestRelatedOriginsClient::new().map_err(|e| format!("client init: {:?}", e))?;

    let caller_origin = "https://www.amazon.com";
    let rp_id = "amazon.com";

        let res = validate_related_origins(caller_origin, rp_id, &client, 100usize).await?;
    assert!(res, "Expected related origins validation to succeed for Amazon");
    Ok(())
}

use std::env;

#[tokio::main]
async fn main() {
    let caller = env::var("RELATED_CALLER").unwrap_or_else(|_| "https://www.amazon.co.uk".to_string());
    let rp_id = env::var("RELATED_RP_ID").unwrap_or_else(|_| "amazon.com".to_string());

    println!("caller: {}", caller);
    println!("rp_id: {}", rp_id);

    match libwebauthn::ops::webauthn::related_origins::validate_related_origins(&caller, &rp_id).await {
        Ok(valid) => println!("validate_related_origins => {}", valid),
        Err(e) => eprintln!("error: {:#?}", e),
    }
}

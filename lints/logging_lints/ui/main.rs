// Test fixtures for the logging lints. Local dummy macros stand in for the
// tracing/log macros: the lints run before expansion and match by macro name,
// so the bodies are irrelevant.

macro_rules! trace {
    ($($t:tt)*) => {{}};
}
macro_rules! debug {
    ($($t:tt)*) => {{}};
}
macro_rules! info {
    ($($t:tt)*) => {{}};
}
macro_rules! warn {
    ($($t:tt)*) => {{}};
}
macro_rules! error {
    ($($t:tt)*) => {{}};
}

fn main() {
    let count = 3u32;
    let err = "boom";
    let pin = 1234u32;
    let shared_secret = [0u8; 32];

    // OK: static message, structured fields.
    info!("Listing devices");
    warn!(?err, "Authenticator returned a malformed response");
    debug!(count, "Filtered credentials");
    trace!(?shared_secret, "Raw shared secret"); // OK: trace may carry secrets

    // tracing_message_interpolation
    info!("found {} credentials", count);
    debug!("found {count} credentials");
    error!("failed: {err:?}");
    warn!(?err, "failed after {} tries", count);

    // print_macro_in_library
    println!("hello {}", count);
    eprintln!("oops");
    print!("no newline");

    // sensitive_field_above_debug
    warn!(?pin, "logging a pin at warn");
    error!(?shared_secret, "logging a secret at error");
    // OK: sensitive name but only at debug, and benign pin metadata.
    debug!(?pin, "pin at debug is allowed");
    info!(pin_protocol = count, "pin protocol is benign");
    info!(pin_len = count, "a length is benign");

    // sensitive_field_above_debug inside a brace block (the policy form for 2+ fields)
    let bar = 7u32;
    warn!({ pin = ?pin, attempt = count }, "pin in a brace block");
    error!({ ?shared_secret, attempt = count }, "secret in a brace block");
    // OK: brace block of benign fields, and a brace block at debug
    info!({ rp_id = bar, attempt = count }, "benign brace block");
    debug!({ pin = ?pin, attempt = count }, "pin in a brace block at debug is allowed");

    // print_macro_in_library: std-qualified
    std::println!("qualified {}", count);

    // tracing_message_interpolation: dynamic message field
    info!(message = %count, attempt = count);
}

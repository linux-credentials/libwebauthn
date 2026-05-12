use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use libwebauthn::pin::PinManagement;
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use text_io::read;

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    for mut device in devices {
        println!("Selected HID authenticator: {}", device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        print!("PIN: Please enter the _new_ PIN: ");
        io::stdout().flush().unwrap();
        let new_pin: String = read!("{}\n");

        if new_pin.is_empty() {
            println!("PIN: No PIN provided, cancelling operation.");
            return Ok(());
        }

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        retry_user_errors!(channel.change_pin(new_pin.clone(), TIMEOUT)).unwrap();
        println!("PIN changed successfully.");
    }

    Ok(())
}
